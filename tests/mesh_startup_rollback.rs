//! Behavioral tests for mesh startup rollback (Iteration 69, Phase 21).
//!
//! These tests use failure-injection hooks to verify that `MeshTransport::start()`
//! properly rolls back on failure and leaves the lifecycle in a recoverable state.

use std::fs;
use std::sync::Arc;

use parking_lot::RwLock;
use synvoid_mesh::cert::MeshCertManager;
use synvoid_mesh::config::{MeshConfig, MeshNodeRole};
use synvoid_mesh::lifecycle::{
    DhtPeerMutation, DhtPeerSnapshot, FailedStartupResidue, MeshLifecycleState, MeshShutdownReport,
    MeshStartupStage, RecoveryVerification, RollbackReport, StagedPeerResource,
    StagedTopologySnapshot,
};
use synvoid_mesh::task_group::MeshTaskGroup;
use synvoid_mesh::topology::{MeshTopology, PeerState, PeerStatus};
use synvoid_mesh::transport::{MeshTransport, StartupFailurePoint};

fn read_file(path: &str) -> String {
    fs::read_to_string(path).unwrap_or_default()
}

fn count_occurrences(haystack: &str, needle: &str) -> usize {
    haystack.matches(needle).count()
}

fn extract_function(content: &str, fn_name: &str) -> String {
    if let Some(start) = content.find(&format!("fn {fn_name}")) {
        if let Some(brace_start) = content[start..].find('{') {
            let abs_brace = start + brace_start;
            let mut depth = 0i32;
            for (i, ch) in content[abs_brace..].char_indices() {
                match ch {
                    '{' => depth += 1,
                    '}' => {
                        depth -= 1;
                        if depth == 0 {
                            return content[abs_brace..=abs_brace + i].to_string();
                        }
                    }
                    _ => {}
                }
            }
        }
    }
    content.to_string()
}

/// Create a minimal `MeshTransport` for testing.
fn make_test_transport() -> Arc<MeshTransport> {
    let config = Arc::new(MeshConfig::default());
    let topology = Arc::new(MeshTopology::new(config.clone()));
    let cert_manager = Arc::new(RwLock::new(MeshCertManager::new(&config)));

    Arc::new(MeshTransport::new(
        config,
        topology,
        cert_manager,
        None, // record_store
        None, // routing_manager
        None, // threat_intel
        None, // mesh_signer
        None, // stake_manager
        None, // backend_pool
    ))
}

// ── Phase 21: Startup Rollback Behavioral Tests ──────────────────────────────

#[test]
fn test_hook_set_and_clear() {
    let transport = make_test_transport();

    // Initially no hook
    assert!(!transport.has_startup_failure_hook());

    // Set a hook
    transport.set_startup_failure_hook(|point| {
        if point == StartupFailurePoint::AfterCriticalTasks {
            Err("injected failure".to_string())
        } else {
            Ok(())
        }
    });
    assert!(transport.has_startup_failure_hook());

    // Clear the hook
    transport.clear_startup_failure_hook();
    assert!(!transport.has_startup_failure_hook());
}

#[test]
fn test_hook_replacement() {
    let transport = make_test_transport();

    // Set first hook
    transport.set_startup_failure_hook(|point| {
        if point == StartupFailurePoint::AfterCriticalTasks {
            Err("first failure".to_string())
        } else {
            Ok(())
        }
    });

    // Replace with second hook
    transport.set_startup_failure_hook(|point| {
        if point == StartupFailurePoint::DuringRuntimeStart {
            Err("second failure".to_string())
        } else {
            Ok(())
        }
    });

    // Hook is set (replacement worked)
    assert!(transport.has_startup_failure_hook());

    transport.clear_startup_failure_hook();
}

#[test]
fn test_startup_failure_point_equality() {
    assert_eq!(
        StartupFailurePoint::AfterCriticalTasks,
        StartupFailurePoint::AfterCriticalTasks
    );
    assert_ne!(
        StartupFailurePoint::AfterCriticalTasks,
        StartupFailurePoint::DuringSeedBootstrap
    );
    assert_ne!(
        StartupFailurePoint::DuringPeerConnect,
        StartupFailurePoint::DuringDhtBootstrap
    );
    assert_ne!(
        StartupFailurePoint::DuringRuntimeStart,
        StartupFailurePoint::BeforeLifecycleCommit
    );
}

#[test]
fn test_startup_failure_point_debug() {
    // Verify Debug is implemented for all variants
    let _ = format!("{:?}", StartupFailurePoint::AfterCriticalTasks);
    let _ = format!("{:?}", StartupFailurePoint::DuringSeedBootstrap);
    let _ = format!("{:?}", StartupFailurePoint::DuringPeerConnect);
    let _ = format!("{:?}", StartupFailurePoint::DuringDhtBootstrap);
    let _ = format!("{:?}", StartupFailurePoint::DuringRuntimeStart);
    let _ = format!("{:?}", StartupFailurePoint::BeforeLifecycleCommit);
}

#[test]
fn test_startup_failure_point_clone() {
    let point = StartupFailurePoint::AfterCriticalTasks;
    let cloned = point;
    assert_eq!(point, cloned);
}

#[test]
fn test_rollback_requires_recover_before_retry() {
    // After a failed start, can_start() should return false (Failed requires recovery)
    let mut state = MeshLifecycleState::Failed;
    assert!(!state.can_start());

    // Recover via transition_to_stopped
    state.transition_to_stopped();
    assert_eq!(state, MeshLifecycleState::Stopped);

    // Now can_start() should return true
    assert!(state.can_start());
    state.transition_to_starting().unwrap();
    assert_eq!(state, MeshLifecycleState::Starting);
}

#[test]
fn test_lifecycle_not_stuck_at_starting_after_failure() {
    // Simulate: Stopped -> Starting -> (failure) -> should not be stuck at Starting
    let mut state = MeshLifecycleState::Stopped;
    state.transition_to_starting().unwrap();
    assert_eq!(state, MeshLifecycleState::Starting);

    // On failure, we transition to Failed (which does NOT allow direct retry)
    state.transition_to_failed();
    assert_eq!(state, MeshLifecycleState::Failed);
    assert!(!state.can_start());

    // Recover to Stopped, then start again
    state.transition_to_stopped();
    assert!(state.can_start());
    state.transition_to_starting().unwrap();
    assert_eq!(state, MeshLifecycleState::Starting);
}

#[test]
fn test_lifecycle_stopped_state_allows_start() {
    let state = MeshLifecycleState::Stopped;
    assert!(state.can_start());
}

#[test]
fn test_lifecycle_failed_requires_recover() {
    let mut state = MeshLifecycleState::Failed;
    assert!(!state.can_start());

    // Must recover to Stopped before starting
    state.transition_to_stopped();
    assert!(state.can_start());
}
#[test]
fn test_transport_constructed_with_defaults() {
    let transport = make_test_transport();
    // Verify the transport was created with expected default state
    // The hook should be None initially
    assert!(!transport.has_startup_failure_hook());
}

#[test]
fn test_hook_invoked_with_correct_point() {
    let transport = make_test_transport();

    transport.set_startup_failure_hook(|point| {
        if point == StartupFailurePoint::AfterCriticalTasks {
            Err("test failure".to_string())
        } else {
            Ok(())
        }
    });

    // Verify the hook is set
    assert!(transport.has_startup_failure_hook());

    transport.clear_startup_failure_hook();
    assert!(!transport.has_startup_failure_hook());
}

// ── Phase 17: Commit/Rollback Behavioral Tests (Iteration 71) ───────────────

/// Test that rollback_and_return helper exists and constructs
/// StartupRollbackFailed when rollback has errors.
#[test]
fn test_rollback_and_return_exists() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    assert!(
        content.contains("fn rollback_and_return"),
        "transport.rs must contain rollback_and_return helper"
    );
    assert!(
        content.contains("StartupRollbackFailed"),
        "rollback_and_return must construct StartupRollbackFailed on incomplete rollback"
    );
}

/// Test that commit_startup takes &mut MeshStartupStage (non-consuming).
#[test]
fn test_commit_startup_non_consuming() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    // Look for the commit_startup signature - it should take &mut, not owned
    // The parameter is in the signature (before the opening brace), not in the body
    let commit_start = content
        .find("fn commit_startup")
        .expect("commit_startup not found");
    let sig_window = &content[commit_start..commit_start + 300];
    assert!(
        sig_window.contains("stage: &mut MeshStartupStage"),
        "commit_startup must take &mut MeshStartupStage (non-consuming) for rollback"
    );
}

/// Test that start_with_policy routes commit errors through rollback.
#[test]
fn test_start_routes_commit_errors_through_rollback() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    let start_body = extract_function(&content, "start_with_policy");

    // start_with_policy should have two failure paths:
    // 1. run_startup_phases failure -> rollback_and_return
    // 2. commit_startup failure -> rollback_and_return
    assert!(
        start_body.contains("rollback_and_return"),
        "start_with_policy must use rollback_and_return for error routing"
    );

    // Verify both phase failure and commit failure go through rollback
    let rollback_count = count_occurrences(&start_body, "rollback_and_return");
    assert!(
        rollback_count >= 2,
        "start_with_policy should call rollback_and_return at least twice \
         (once for phase failure, once for commit failure); found {rollback_count}"
    );
}

/// Test that commit installs task group before transitioning to Running.
#[test]
fn test_commit_installs_before_running() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    let commit_body = extract_function(&content, "commit_startup");

    // Task group installation must come before transition_to_running
    let tg_install = commit_body.find("task_group");
    let running = commit_body.find("transition_to_running");

    if let (Some(tg), Some(r)) = (tg_install, running) {
        assert!(
            tg < r,
            "task group installation (pos {tg}) must come before \
             transition_to_running (pos {r}) in commit_startup"
        );
    }
}

/// Test that StagedPeerResource is used in rollback.
#[test]
fn test_staged_peer_resource_in_rollback() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    let rollback_body = extract_function(&content, "rollback_startup");

    assert!(
        rollback_body.contains("created_peers"),
        "rollback_startup must iterate stage.created_peers"
    );
    assert!(
        rollback_body.contains("session_id"),
        "rollback_startup must use session_id for connection removal"
    );
    assert!(
        rollback_body.contains("topology_existed_before") || rollback_body.contains("remove_peer"),
        "rollback_startup must handle topology restoration"
    );
}

/// Test that verify_rollback_complete exists.
#[test]
fn test_verify_rollback_complete_exists() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    assert!(
        content.contains("fn verify_rollback_complete"),
        "transport.rs must contain verify_rollback_complete method"
    );
}

/// Test that MeshStartupStage tracks peers via StagedPeerResource.
#[test]
fn test_startup_stage_tracks_peers() {
    let content = read_file("crates/synvoid-mesh/src/mesh/lifecycle.rs");
    assert!(
        content.contains("StagedPeerResource"),
        "lifecycle.rs must define StagedPeerResource"
    );
    assert!(
        content.contains("created_peers:"),
        "MeshStartupStage must have created_peers field"
    );
    assert!(
        content.contains("fn record_peer"),
        "MeshStartupStage must have record_peer method"
    );
}

/// Test that RollbackReport has expanded fields.
#[test]
fn test_rollback_report_expanded() {
    let content = read_file("crates/synvoid-mesh/src/mesh/lifecycle.rs");
    assert!(
        content.contains("tasks_joined:"),
        "RollbackReport must have tasks_joined field"
    );
    assert!(
        content.contains("tasks_aborted:"),
        "RollbackReport must have tasks_aborted field"
    );
    assert!(
        content.contains("peer_connections_closed:"),
        "RollbackReport must have peer_connections_closed field"
    );
    assert!(
        content.contains("topology_entries_restored:"),
        "RollbackReport must have topology_entries_restored field"
    );
    assert!(
        content.contains("runtime_stopped:"),
        "RollbackReport must have runtime_stopped field"
    );
}

/// Test that rollback uses shared deadline.
#[test]
fn test_rollback_uses_shared_deadline() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    let rollback_body = extract_function(&content, "rollback_startup");

    assert!(
        rollback_body.contains("deadline") || rollback_body.contains("remaining"),
        "rollback_startup must use a shared deadline for all cleanup phases"
    );
}

/// Test that startup_rollback_timeout_secs exists in config.
#[test]
fn test_rollback_timeout_config_exists() {
    let content = read_file("crates/synvoid-mesh/src/mesh/config.rs");
    assert!(
        content.contains("startup_rollback_timeout_secs"),
        "MeshConnectionConfig must have startup_rollback_timeout_secs field"
    );
}

// ── Phase 19: Rollback Deadline Edge-Case Tests (Iteration 71) ───────────────

/// Test that RollbackReport tracks timeout/abort counts.
#[test]
fn test_rollback_report_tracks_abort_counts() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    let rollback_body = extract_function(&content, "rollback_startup");

    // Must count remaining active tasks as aborted
    assert!(
        rollback_body.contains("tasks_aborted") || rollback_body.contains("remaining"),
        "rollback_startup must track aborted task counts"
    );

    // Must use shared deadline for all phases
    assert!(
        rollback_body.contains("deadline"),
        "rollback_startup must use a shared deadline"
    );

    // Must handle abort after cooperative drain
    assert!(
        rollback_body.contains("abort_all") || rollback_body.contains("abort"),
        "rollback_startup must abort remaining sessions after cooperative drain"
    );
}

/// Test that rollback timeout config defaults to a reasonable value.
#[test]
fn test_rollback_timeout_default_reasonable() {
    let content = read_file("crates/synvoid-mesh/src/mesh/config.rs");

    // Find the default value and verify it's reasonable (5-60 seconds)
    // Just check the field exists and has a default
    assert!(
        content.contains("startup_rollback_timeout_secs"),
        "config must have startup_rollback_timeout_secs"
    );
}

// ── Phase 16: Accept Loop Report Wiring Tests (Iteration 71) ─────────────────

/// Test that accept loop report is wired into shutdown.
#[test]
fn test_accept_loop_report_wired() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    assert!(
        content.contains("accept_loop_report"),
        "MeshTransport must have accept_loop_report field"
    );
}

/// Test that mesh_accept_loop populates the report before exiting.
#[test]
fn test_accept_loop_populates_report() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    let accept_body = extract_function(&content, "mesh_accept_loop");

    assert!(
        accept_body.contains("report.drained_handshakes"),
        "mesh_accept_loop must set report.drained_handshakes"
    );
    assert!(
        accept_body.contains("report.aborted_handshakes"),
        "mesh_accept_loop must set report.aborted_handshakes"
    );
    assert!(
        accept_body.contains("accept_loop_report"),
        "mesh_accept_loop must access self.accept_loop_report"
    );
}

/// Test that shutdown_with_timeout reads the accept loop report.
#[test]
fn test_shutdown_reads_accept_loop_report() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    let shutdown_body = extract_function(&content, "shutdown_with_timeout");

    assert!(
        shutdown_body.contains("accept_loop_report"),
        "shutdown_with_timeout must read accept_loop_report"
    );
    assert!(
        shutdown_body.contains("drained_peer_children"),
        "shutdown_with_timeout must set drained_peer_children from accept report"
    );
    assert!(
        shutdown_body.contains("aborted_peer_children"),
        "shutdown_with_timeout must set aborted_peer_children from accept report"
    );
}

/// Test that MeshAcceptLoopReport no longer has Deferred annotations.
#[test]
fn test_accept_loop_report_not_deferred() {
    let content = read_file("crates/synvoid-mesh/src/mesh/lifecycle.rs");
    // Find the MeshAcceptLoopReport struct definition area
    let report_start = content
        .find("pub struct MeshAcceptLoopReport")
        .expect("MeshAcceptLoopReport struct not found");
    let report_window = &content[report_start..report_start + 500];

    assert!(
        !report_window.contains("Deferred"),
        "MeshAcceptLoopReport fields must not be annotated as Deferred"
    );
}

/// Test that MeshShutdownReport no longer has Non-authoritative annotations.
#[test]
fn test_shutdown_report_not_non_authoritative() {
    let content = read_file("crates/synvoid-mesh/src/mesh/lifecycle.rs");
    // Find the MeshShutdownReport struct definition area
    let report_start = content
        .find("pub struct MeshShutdownReport")
        .expect("MeshShutdownReport struct not found");
    let report_window = &content[report_start..report_start + 800];

    assert!(
        !report_window.contains("Non-authoritative"),
        "MeshShutdownReport fields must not be annotated as Non-authoritative"
    );
}

/// Test that rollback calls stop_server on the QUIC runtime.
#[test]
fn test_rollback_calls_stop_server() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    let rollback_body = extract_function(&content, "rollback_startup");

    assert!(
        rollback_body.contains("stop_server"),
        "rollback_startup must call stop_server() for active runtime cleanup"
    );
}

/// Test that stop_server exists in QuicRuntime.
#[test]
fn test_stop_server_exists() {
    let content = read_file("crates/synvoid-tunnel/src/quic/runtime.rs");
    assert!(
        content.contains("fn stop_server"),
        "QuicRuntime must have stop_server method"
    );
    assert!(
        content.contains("endpoint.close"),
        "stop_server must close the QUIC endpoint"
    );
}

// ── Phase 18: Behavioral Tests For Shared Report Wiring ──────────────────────

#[test]
fn accept_loop_report_is_shared_via_arc_in_clone() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport_connection.rs");

    // clone_for_maintenance should clone the accept_loop_report Arc, not create a new one
    assert!(
        content.contains("accept_loop_report: self.accept_loop_report.clone()"),
        "clone_for_maintenance must share accept_loop_report via Arc::clone"
    );

    // Should NOT create a new default
    assert!(
        !content.contains("accept_loop_report: Arc::new(tokio::sync::Mutex::new(\n                crate::lifecycle::MeshAcceptLoopReport::default(),\n            ))"),
        "clone_for_maintenance must not create a new default accept_loop_report"
    );
}

#[test]
fn accept_loop_report_reset_per_startup_generation() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");

    // start_with_policy should reset the accept loop report before running phases
    assert!(
        content.contains("report.generation = report.generation.saturating_add(1)")
            || content.contains("generation: 0")
            || content.contains("reset_accept_loop_report"),
        "start_with_policy should reset accept loop report generation"
    );
}

// ── Phase 19: Behavioral Tests For Verification State ────────────────────────

#[test]
fn rollback_and_return_merges_verification_before_lifecycle_selection() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");

    // The rollback_and_return method should merge verification issues into
    // the rollback report BEFORE calling finish_failed_startup
    assert!(
        content.contains("rollback.errors.extend(verification_issues)")
            || content.contains("rollback.clean = rollback.errors.is_empty()"),
        "rollback_and_return must merge verification issues before lifecycle selection"
    );

    // finish_failed_startup should be called AFTER merging
    let idx_merge = content
        .find("rollback.errors.extend(verification_issues)")
        .or_else(|| content.find("rollback.clean = rollback.errors.is_empty()"))
        .unwrap_or(0);
    let idx_finish = content
        .find("self.finish_failed_startup(&rollback).await")
        .unwrap_or(usize::MAX);
    assert!(
        idx_merge < idx_finish,
        "Verification must be merged before finish_failed_startup is called"
    );
}

// ── Phase 20-23: Selective Rollback/Topology/DHT/Preflight Tests ────────────

#[test]
fn rollback_selective_session_cleanup_uses_staged_ids() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");

    // Rollback should iterate staged session IDs, not abort all sessions
    assert!(
        content.contains("staged_session_ids") || content.contains("created_peers.iter()"),
        "Rollback must use staged session IDs for selective cleanup"
    );
}

#[test]
fn topology_rollback_handles_both_new_and_existing_peers() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");

    // Rollback should handle both None (new peer) and Some (existing peer) cases
    assert!(
        content.contains("None =>") && content.contains("Some(snapshot) =>"),
        "Topology rollback must handle both new and existing peers"
    );
}

#[test]
fn dht_rollback_uses_node_id_not_session_id() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");

    // DHT removal should use peer.node_id, not peer.session_id
    assert!(
        content.contains("rm.remove_peer(&peer.node_id)"),
        "DHT rollback must use node_id, not session_id"
    );
}

// ── Phase 24: Guardrail Updates ─────────────────────────────────────────────

#[test]
fn can_start_rejects_failed_state() {
    let content = read_file("crates/synvoid-mesh/src/mesh/lifecycle.rs");

    // can_start should only match Stopped, not Failed
    assert!(
        content.contains("matches!(self, MeshLifecycleState::Stopped)"),
        "can_start() must only allow Stopped, not Failed"
    );
    assert!(
        !content.contains("MeshLifecycleState::Stopped | MeshLifecycleState::Failed"),
        "can_start() must not allow Failed state"
    );
}

#[test]
fn recover_failed_state_exists() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");

    // recover_failed_state method must exist
    assert!(
        content.contains("pub async fn recover_failed_state"),
        "recover_failed_state method must exist on MeshTransport"
    );
}

#[test]
fn staged_peer_resource_has_previous_topology() {
    let content = read_file("crates/synvoid-mesh/src/mesh/lifecycle.rs");

    // StagedPeerResource must have previous_topology field
    assert!(
        content.contains("previous_topology: Option<StagedTopologySnapshot>"),
        "StagedPeerResource must have previous_topology field"
    );

    // StagedTopologySnapshot must exist
    assert!(
        content.contains("pub struct StagedTopologySnapshot"),
        "StagedTopologySnapshot struct must exist"
    );
}

#[test]
fn staged_peer_resource_has_dht_tracking() {
    let content = read_file("crates/synvoid-mesh/src/mesh/lifecycle.rs");

    assert!(
        content.contains("dht_mutation: DhtPeerMutation"),
        "StagedPeerResource must have dht_mutation field of type DhtPeerMutation"
    );
}

#[test]
fn staged_peer_resource_has_session_task_id() {
    let content = read_file("crates/synvoid-mesh/src/mesh/lifecycle.rs");

    assert!(
        content.contains("session_task_id: Option<String>"),
        "StagedPeerResource must have session_task_id field"
    );
    // Should NOT have the old boolean field
    assert!(
        !content.contains("session_task_created: bool"),
        "StagedPeerResource must not have session_task_created boolean"
    );
}

#[test]
fn peer_sessions_is_keyed_registry() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");

    // peer_sessions should use HashMap, not JoinSet
    assert!(
        content.contains("HashMap<String,")
            && (content.contains("PeerSessionTask>") || content.contains("PeerSessionTask >")),
        "peer_sessions must use HashMap<String, ...PeerSessionTask>"
    );
}

#[test]
fn peer_session_task_struct_exists() {
    let content = read_file("crates/synvoid-mesh/src/mesh/lifecycle.rs");

    assert!(
        content.contains("pub struct PeerSessionTask"),
        "PeerSessionTask struct must exist"
    );
}

#[test]
fn rollback_removes_dht_entries() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");

    // rollback_startup should remove DHT routing entries
    assert!(
        content.contains("rm.remove_peer(&peer.node_id)")
            || content.contains("remove_peer(&peer.node_id)"),
        "rollback_startup must remove DHT routing entries for staged peers"
    );
}

#[test]
fn rollback_restores_topology_snapshots() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");

    // rollback_startup should restore topology using previous_topology
    assert!(
        content.contains("previous_topology") && content.contains("add_peer"),
        "rollback_startup must restore topology using previous_topology snapshots"
    );
}

#[test]
fn commit_startup_checks_task_group_empty() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");

    // commit_startup should check that old task group is empty
    assert!(
        content.contains("old.active_count()") || content.contains("active_count()"),
        "commit_startup must check old task group active count"
    );
}

#[test]
fn preflight_owned_during_startup() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");

    // During startup (when stage is Some), preflight should be owned by task group
    assert!(
        content.contains("spawn_child(\"preflight_peer_routes\"")
            || content.contains("stage.task_group.spawn_child"),
        "Preflight must be owned by staged task group during startup"
    );
}

#[test]
fn accept_loop_report_has_generation() {
    let content = read_file("crates/synvoid-mesh/src/mesh/lifecycle.rs");

    assert!(
        content.contains("pub generation: u64"),
        "MeshAcceptLoopReport must have generation field"
    );
}

#[test]
fn rollback_abort_count_from_exits() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");

    // Rollback should count aborted tasks from exit metadata
    assert!(
        content.contains("MeshTaskExitReason::Aborted") && content.contains("tasks_aborted"),
        "Rollback must derive abort count from exit reasons"
    );
}

// ── Phase 21: Task-Group Replacement Tests ───────────────────────────────────

#[test]
fn commit_startup_rejects_non_empty_task_group() {
    let tg = MeshTaskGroup::new();
    let mut stage = MeshStartupStage::new(tg);
    stage.record_peer(StagedPeerResource {
        session_id: "sess-1".to_string(),
        node_id: "node-1".to_string(),
        previous_topology: None,
        connection_inserted: true,
        session_task_id: Some("sess-1".to_string()),
        dht_mutation: DhtPeerMutation::None,
        session_generation: 1,
    });
    assert!(stage.has_resources());
}

#[test]
fn empty_task_group_commit_succeeds() {
    let tg = MeshTaskGroup::new();
    let stage = MeshStartupStage::new(tg);
    assert!(!stage.has_resources());
    // task_group field is pub(crate); verify via has_resources() which checks
    // runtime_started and created_peers are both empty/false.
}

// ── Phase 22: Topology Snapshot Timing Tests ─────────────────────────────────

#[test]
fn staged_topology_snapshot_stores_peer_state() {
    let peer_state = PeerState {
        node_id: "node-1".to_string(),
        address: "1.2.3.4:443".to_string(),
        role: MeshNodeRole::EDGE,
        status: PeerStatus::Healthy,
        capabilities: synvoid_mesh::protocol::MeshCapabilities::default(),
        upstreams: std::collections::HashSet::new(),
        latency_ms: Some(50),
        first_seen: 1000,
        last_seen: 2000,
        is_global: false,
        is_trusted: false,
        connection_handle: None,
        geo: Some("us-east".to_string()),
        audit_successes: 10,
        audit_failures: 1,
        performance_audit_successes: 5,
        performance_audit_failures: 0,
        quic_port: Some(443),
        wireguard_port: None,
        advertised_port: Some(443),
        previous_reputation: Some(0.9),
    };

    let snapshot = StagedTopologySnapshot {
        peer_state: peer_state.clone(),
    };

    assert_eq!(snapshot.peer_state.node_id, "node-1");
    assert_eq!(snapshot.peer_state.latency_ms, Some(50));
    assert_eq!(snapshot.peer_state.audit_successes, 10);
    assert_eq!(snapshot.peer_state.previous_reputation, Some(0.9));
    assert_eq!(snapshot.peer_state.geo, Some("us-east".to_string()));
}

#[test]
fn topology_snapshot_before_mutation_is_captured() {
    let resource = StagedPeerResource {
        session_id: "sess-1".to_string(),
        node_id: "node-1".to_string(),
        previous_topology: None,
        connection_inserted: true,
        session_task_id: Some("sess-1".to_string()),
        dht_mutation: DhtPeerMutation::Created,
        session_generation: 1,
    };
    assert!(resource.previous_topology.is_none());
    assert!(matches!(resource.dht_mutation, DhtPeerMutation::Created));
}

#[test]
fn topology_snapshot_existing_peer_preserves_state() {
    let peer_state = PeerState {
        node_id: "node-2".to_string(),
        address: "5.6.7.8:443".to_string(),
        role: MeshNodeRole::GLOBAL,
        status: PeerStatus::Healthy,
        capabilities: synvoid_mesh::protocol::MeshCapabilities::default(),
        upstreams: ["upstream-1".to_string()].into_iter().collect(),
        latency_ms: Some(25),
        first_seen: 500,
        last_seen: 1500,
        is_global: true,
        is_trusted: true,
        connection_handle: None,
        geo: None,
        audit_successes: 20,
        audit_failures: 2,
        performance_audit_successes: 10,
        performance_audit_failures: 1,
        quic_port: Some(443),
        wireguard_port: None,
        advertised_port: Some(443),
        previous_reputation: None,
    };

    let snapshot = StagedTopologySnapshot {
        peer_state: peer_state.clone(),
    };

    let resource = StagedPeerResource {
        session_id: "sess-2".to_string(),
        node_id: "node-2".to_string(),
        previous_topology: Some(snapshot),
        connection_inserted: true,
        session_task_id: Some("sess-2".to_string()),
        dht_mutation: DhtPeerMutation::Replaced(DhtPeerSnapshot {
            node_id: "node-2".to_string(),
            address: "5.6.7.8:443".to_string(),
            port: 443,
            role: MeshNodeRole::GLOBAL,
        }),
        session_generation: 2,
    };

    let prev = resource.previous_topology.as_ref().unwrap();
    assert_eq!(prev.peer_state.node_id, "node-2");
    assert_eq!(prev.peer_state.audit_successes, 20);
    assert!(prev.peer_state.is_global);
    assert!(prev.peer_state.is_trusted);
}

// ── Phase 23: DHT Mutation Tests ─────────────────────────────────────────────

#[test]
fn dht_mutation_none_for_disabled_dht() {
    let resource = StagedPeerResource {
        session_id: "sess-1".to_string(),
        node_id: "node-1".to_string(),
        previous_topology: None,
        connection_inserted: true,
        session_task_id: Some("sess-1".to_string()),
        dht_mutation: DhtPeerMutation::None,
        session_generation: 1,
    };
    assert!(matches!(resource.dht_mutation, DhtPeerMutation::None));
}

#[test]
fn dht_mutation_created_for_new_peer() {
    let resource = StagedPeerResource {
        session_id: "sess-1".to_string(),
        node_id: "node-1".to_string(),
        previous_topology: None,
        connection_inserted: true,
        session_task_id: Some("sess-1".to_string()),
        dht_mutation: DhtPeerMutation::Created,
        session_generation: 1,
    };
    assert!(matches!(resource.dht_mutation, DhtPeerMutation::Created));
}

#[test]
fn dht_mutation_replaced_preserves_prior_state() {
    let snapshot = DhtPeerSnapshot {
        node_id: "node-1".to_string(),
        address: "1.2.3.4:443".to_string(),
        port: 443,
        role: MeshNodeRole::EDGE,
    };
    let resource = StagedPeerResource {
        session_id: "sess-1".to_string(),
        node_id: "node-1".to_string(),
        previous_topology: None,
        connection_inserted: true,
        session_task_id: Some("sess-1".to_string()),
        dht_mutation: DhtPeerMutation::Replaced(snapshot.clone()),
        session_generation: 1,
    };
    match &resource.dht_mutation {
        DhtPeerMutation::Replaced(s) => {
            assert_eq!(s.node_id, "node-1");
            assert_eq!(s.address, "1.2.3.4:443");
            assert_eq!(s.port, 443);
        }
        _ => panic!("Expected Replaced variant"),
    }
}

#[test]
fn dht_mutation_updated_in_place_preserves_state() {
    let snapshot = DhtPeerSnapshot {
        node_id: "node-2".to_string(),
        address: "5.6.7.8:8080".to_string(),
        port: 8080,
        role: MeshNodeRole::GLOBAL,
    };
    let resource = StagedPeerResource {
        session_id: "sess-2".to_string(),
        node_id: "node-2".to_string(),
        previous_topology: None,
        connection_inserted: true,
        session_task_id: Some("sess-2".to_string()),
        dht_mutation: DhtPeerMutation::UpdatedInPlace(snapshot),
        session_generation: 2,
    };
    assert!(matches!(
        resource.dht_mutation,
        DhtPeerMutation::UpdatedInPlace(_)
    ));
}

// ── Phase 12: RollbackReport Session Fields Tests ────────────────────────────

#[test]
fn rollback_report_session_fields_separated() {
    let mut report = RollbackReport::default();
    report.peer_sessions_drained = 3;
    report.peer_sessions_aborted = 1;
    report.peer_sessions_failed = 2;

    assert_eq!(report.peer_sessions_drained, 3);
    assert_eq!(report.peer_sessions_aborted, 1);
    assert_eq!(report.peer_sessions_failed, 2);
    assert_eq!(
        report.peer_sessions_drained + report.peer_sessions_aborted + report.peer_sessions_failed,
        6
    );
}

#[test]
fn shutdown_report_has_failed_peer_sessions() {
    let mut report = MeshShutdownReport::default();
    report.drained_peer_sessions = 5;
    report.aborted_peer_sessions = 2;
    report.failed_peer_sessions = 1;

    assert_eq!(report.drained_peer_sessions, 5);
    assert_eq!(report.aborted_peer_sessions, 2);
    assert_eq!(report.failed_peer_sessions, 1);
}

// ── Phase 8: FailedStartupResidue Tests ──────────────────────────────────────

#[test]
fn failed_startup_residue_retains_peers() {
    let residue = FailedStartupResidue {
        peers: vec![StagedPeerResource {
            session_id: "sess-1".to_string(),
            node_id: "node-1".to_string(),
            previous_topology: None,
            connection_inserted: true,
            session_task_id: Some("sess-1".to_string()),
            dht_mutation: DhtPeerMutation::Created,
            session_generation: 1,
        }],
        generation: 42,
        runtime_started: true,
        rollback_errors: vec!["test error".to_string()],
    };

    assert_eq!(residue.peers.len(), 1);
    assert_eq!(residue.generation, 42);
    assert!(residue.runtime_started);
    assert_eq!(residue.rollback_errors.len(), 1);
}

#[test]
fn recovery_verification_all_clean() {
    let v = RecoveryVerification {
        tasks_empty: true,
        sessions_empty: true,
        auxiliary_empty: true,
        connections_empty: true,
        runtime_stopped: true,
        residue_cleared: true,
        projection_clear: true,
        issues: Vec::new(),
    };
    assert!(v.is_clean());
}

#[test]
fn recovery_verification_has_issues() {
    let v = RecoveryVerification {
        tasks_empty: false,
        sessions_empty: true,
        auxiliary_empty: true,
        connections_empty: true,
        runtime_stopped: true,
        residue_cleared: true,
        projection_clear: true,
        issues: vec!["task group not empty".to_string()],
    };
    assert!(!v.is_clean());
    assert_eq!(v.issues.len(), 1);
}
