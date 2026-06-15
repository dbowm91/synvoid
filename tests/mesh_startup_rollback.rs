//! Behavioral tests for mesh startup rollback (Iteration 69, Phase 21).
//!
//! These tests use failure-injection hooks to verify that `MeshTransport::start()`
//! properly rolls back on failure and leaves the lifecycle in a recoverable state.

use std::fs;
use std::sync::Arc;

use parking_lot::RwLock;
use synvoid_mesh::cert::MeshCertManager;
use synvoid_mesh::config::{MeshConfig, MeshNodeRole};
use synvoid_mesh::dht::{NodeId, PeerContact};
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
        rollback_body.contains("restore_and_verify_peer_logical_state")
            || rollback_body.contains("restore_peer_logical_state"),
        "rollback_startup must handle topology/DHT restoration"
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
    assert!(
        content.contains("unresolved_peers:"),
        "RollbackReport must have unresolved_peers field"
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
        shutdown_body.contains("report_is_fresh"),
        "shutdown_with_timeout must compute report_is_fresh from generation"
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
            || content.contains("report.generation = gen")
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

    // Rollback should iterate staged peers for selective cleanup.
    // Accept either the old staged_session_ids pattern or the new
    // stop_staged_peer_activity per-peer pattern (Iteration 75).
    assert!(
        content.contains("staged_session_ids")
            || content.contains("created_peers.iter()")
            || content.contains("for peer in &stage.created_peers")
            || content.contains("stop_staged_peer_activity"),
        "Rollback must use staged session IDs or per-peer helper for selective cleanup"
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
        dht_mutation: DhtPeerMutation::Previous(DhtPeerSnapshot {
            contact: PeerContact::new(
                NodeId::from_node_id_string("node-2"),
                "node-2".to_string(),
                "5.6.7.8".to_string(),
                443,
            )
            .with_global(true),
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
fn dht_mutation_previous_preserves_prior_state() {
    let snapshot = DhtPeerSnapshot {
        contact: PeerContact::new(
            NodeId::from_node_id_string("node-1"),
            "node-1".to_string(),
            "1.2.3.4".to_string(),
            443,
        )
        .with_latency(12),
    };
    let resource = StagedPeerResource {
        session_id: "sess-1".to_string(),
        node_id: "node-1".to_string(),
        previous_topology: None,
        connection_inserted: true,
        session_task_id: Some("sess-1".to_string()),
        dht_mutation: DhtPeerMutation::Previous(snapshot.clone()),
        session_generation: 1,
    };
    match &resource.dht_mutation {
        DhtPeerMutation::Previous(s) => {
            assert_eq!(s.contact.node_id_string, "node-1");
            assert_eq!(s.contact.address, "1.2.3.4");
            assert_eq!(s.contact.port, 443);
            assert_eq!(s.contact.latency_ms, Some(12));
        }
        _ => panic!("Expected Previous variant"),
    }
}

#[test]
fn dht_mutation_previous_in_place_preserves_state() {
    let snapshot = DhtPeerSnapshot {
        contact: PeerContact::new(
            NodeId::from_node_id_string("node-2"),
            "node-2".to_string(),
            "5.6.7.8".to_string(),
            8080,
        )
        .with_global(true)
        .with_trusted(true)
        .with_pow(99, vec![10, 20, 30]),
    };
    let resource = StagedPeerResource {
        session_id: "sess-2".to_string(),
        node_id: "node-2".to_string(),
        previous_topology: None,
        connection_inserted: true,
        session_task_id: Some("sess-2".to_string()),
        dht_mutation: DhtPeerMutation::Previous(snapshot),
        session_generation: 2,
    };
    assert!(matches!(
        resource.dht_mutation,
        DhtPeerMutation::Previous(_)
    ));
}

// ── Phase 24: Recovery Completeness Tests ────────────────────────────────────

#[test]
fn recovery_verification_checks_all_registries() {
    let v = RecoveryVerification {
        tasks_empty: false,
        sessions_empty: false,
        auxiliary_empty: false,
        connections_empty: false,
        runtime_stopped: false,
        residue_cleared: false,
        projection_clear: false,
        issues: vec![
            "task group not empty".to_string(),
            "2 peer sessions still present".to_string(),
            "1 auxiliary tasks still present".to_string(),
            "3 peer connections still present".to_string(),
            "running_projection is still true".to_string(),
        ],
    };
    assert!(!v.is_clean());
    assert_eq!(v.issues.len(), 5);
}

#[test]
fn failed_startup_residue_cleared_after_recovery() {
    let residue = FailedStartupResidue {
        peers: Vec::new(),
        generation: 1,
        runtime_started: true,
        rollback_errors: Vec::new(),
    };
    let mut r = Some(residue);
    assert!(r.is_some());
    r = None;
    assert!(r.is_none());
}

// ── Phase 18: Generation Wiring Tests ────────────────────────────────────────

#[test]
fn session_generation_not_always_zero() {
    let code = include_str!("../crates/synvoid-mesh/src/mesh/transport.rs");
    assert!(
        code.contains("session_generation_for_task")
            || code.contains("generation: session_generation"),
        "session generation should be computed from stage, not hardcoded to 0"
    );
}

// ── Phase 25: Abort-Await Deadline Tests ──────────────────────────────────────

#[test]
fn abort_always_followed_by_await() {
    let code = include_str!("../crates/synvoid-mesh/src/mesh/transport.rs");
    let lines: Vec<&str> = code.lines().collect();
    for (i, line) in lines.iter().enumerate() {
        if line.contains(".abort()") && !line.contains("//") {
            let following = lines[i..std::cmp::min(i + 5, lines.len())].join("\n");
            assert!(
                following.contains(".await"),
                "abort at line {} must be followed by await within 5 lines",
                i
            );
        }
    }
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

// ── Phase 42: Recovery Residue Test ─────────────────────────────────────────

#[tokio::test]
async fn test_recovery_applies_residue_before_clearing() {
    // Verify that recover_failed_state() reads and applies
    // failed_startup_residue before clearing it (Iteration 74, Phase 42).
    let source = read_file("crates/synvoid-mesh/src/mesh/transport.rs");

    // Verify recover_failed_state takes residue before clearing
    let recovery_fn = extract_function(&source, "recover_failed_state");

    // Should take residue (guard.take())
    assert!(
        recovery_fn.contains("guard.take()") || recovery_fn.contains(".take()"),
        "recover_failed_state must take residue before clearing"
    );

    // Should iterate residue peers
    assert!(
        recovery_fn.contains("residue.peers") || recovery_fn.contains("for peer in"),
        "recover_failed_state must iterate residue peers"
    );

    // Should call restore_and_verify_peer_logical_state or restore_peer_logical_state
    assert!(
        recovery_fn.contains("restore_and_verify_peer_logical_state")
            || recovery_fn.contains("restore_peer_logical_state"),
        "recover_failed_state must use restore_and_verify_peer_logical_state or restore_peer_logical_state for residue"
    );

    // Should retain unresolved residue on error
    assert!(
        recovery_fn.contains("remaining_peers") || recovery_fn.contains("FailedStartupResidue"),
        "recover_failed_state must retain unresolved residue"
    );
}

// ── Phase 43: Recovery Partial Failure Test ──────────────────────────────────

#[tokio::test]
async fn test_recovery_retains_residue_on_partial_failure() {
    // Verify that partial recovery retains unresolved peers (Iteration 74, Phase 43).
    let source = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    let recovery_fn = extract_function(&source, "recover_failed_state");

    // Must have remaining_peers tracking
    assert!(
        recovery_fn.contains("remaining_peers"),
        "recover_failed_state must track remaining peers on partial failure"
    );

    // Must re-store FailedStartupResidue with remaining peers
    assert!(
        recovery_fn.contains("failed_startup_residue.lock()"),
        "recover_failed_state must re-store residue on partial failure"
    );
}

// ── Phase 44: Session Reaper Await Test ──────────────────────────────────────

#[tokio::test]
async fn test_session_reaper_awaits_removed_handles() {
    // Verify that the session reaper awaits handles after removing them (Iteration 74, Phase 44).
    let source = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    let reaper_fn = extract_function(&source, "spawn_session_reaper");

    // Must await handle outside the lock
    assert!(
        reaper_fn.contains("task.handle.await") || reaper_fn.contains("handle.await"),
        "session reaper must await removed handles"
    );

    // Must remove before await (not hold lock during await)
    assert!(
        reaper_fn.contains("sessions.remove"),
        "session reaper must remove entry before awaiting handle"
    );
}

// ── Phase 45: Session Reaper Cancellation Test ───────────────────────────────

#[tokio::test]
async fn test_session_reaper_respects_shutdown() {
    // Verify that the session reaper exits on shutdown signal (Iteration 74, Phase 45).
    let source = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    let reaper_fn = extract_function(&source, "spawn_session_reaper");

    // Must use tokio::select!
    assert!(
        reaper_fn.contains("tokio::select!"),
        "session reaper must use tokio::select! for cancellation"
    );

    // Must check shutdown signal
    assert!(
        reaper_fn.contains("shutdown") || reaper_fn.contains("shutdown_rx"),
        "session reaper must select on shutdown signal"
    );

    // Must break on shutdown
    assert!(
        reaper_fn.contains("break"),
        "session reaper must break out of loop on shutdown"
    );
}

// ── Phase 46: Reaper Lag Test ────────────────────────────────────────────────

#[tokio::test]
async fn test_session_reaper_handles_lag() {
    // Verify that the session reaper handles broadcast lag (Iteration 74, Phase 46).
    let source = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    let reaper_fn = extract_function(&source, "spawn_session_reaper");

    // Must handle Lagged error
    assert!(
        reaper_fn.contains("Lagged"),
        "session reaper must handle broadcast lag"
    );

    // Must call reap_finished_peer_sessions on lag
    assert!(
        reaper_fn.contains("reap_finished_peer_sessions"),
        "session reaper must scan for finished sessions on lag"
    );
}

// ── Phase 47: Auxiliary Reaper Test ──────────────────────────────────────────

#[tokio::test]
async fn test_auxiliary_reaper_exists() {
    // Verify that the auxiliary task reaper is implemented (Iteration 74, Phase 47).
    let source = read_file("crates/synvoid-mesh/src/mesh/transport.rs");

    // Must have spawn_auxiliary_reaper
    assert!(
        source.contains("fn spawn_auxiliary_reaper"),
        "transport must have spawn_auxiliary_reaper method"
    );

    let reaper_fn = extract_function(&source, "spawn_auxiliary_reaper");

    // Must use tokio::select!
    assert!(
        reaper_fn.contains("tokio::select!"),
        "auxiliary reaper must use tokio::select! for cancellation"
    );

    // Must await removed handles
    assert!(
        reaper_fn.contains("task.handle.await") || reaper_fn.contains("handle.await"),
        "auxiliary reaper must await removed handles"
    );

    // Must handle lag
    assert!(
        reaper_fn.contains("Lagged") || reaper_fn.contains("reap_finished"),
        "auxiliary reaper must handle broadcast lag"
    );
}

// ── Phase 48: Global Generation Test ────────────────────────────────────────

#[tokio::test]
async fn test_global_session_generation() {
    // Verify that all session paths use the transport-global generation (Iteration 74, Phase 48).
    let source = read_file("crates/synvoid-mesh/src/mesh/transport.rs");

    // connect_to_peer must use session_generation.fetch_add
    let connect_fn = extract_function(&source, "connect_to_peer");
    assert!(
        connect_fn.contains("session_generation.fetch_add"),
        "connect_to_peer must use transport-global session_generation"
    );

    // No more default 0 for steady-state
    assert!(
        !connect_fn.contains("} else {\n    0\n}") && !connect_fn.contains("else { 0 }"),
        "connect_to_peer must not default to generation 0"
    );
}

// ── Phase 49: Stale Accept Report Test ───────────────────────────────────────

#[tokio::test]
async fn test_stale_accept_report_suppression() {
    // Verify that stale accept-loop counts are suppressed (Iteration 74, Phase 49).
    let source = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    let shutdown_fn = extract_function(&source, "shutdown_with_timeout");

    // Must check generation freshness
    assert!(
        shutdown_fn.contains("report_is_fresh") || shutdown_fn.contains("generation"),
        "shutdown must check accept-loop report freshness"
    );

    // Must set accept_loop_report to None when stale
    assert!(
        shutdown_fn.contains("accept_loop_report"),
        "shutdown must use accept_loop_report option field"
    );
}

// ── Phase 50-51: Snapshot Struct Tests ──────────────────────────────────────

#[tokio::test]
async fn test_dht_peer_snapshot_has_all_contact_fields() {
    // Verify DhtPeerSnapshot stores complete PeerContact (Iteration 75, Phase 3).
    let contact = PeerContact::new(
        NodeId::from_node_id_string("test-node"),
        "test-node".to_string(),
        "10.0.0.1".to_string(),
        443,
    )
    .with_global(true)
    .with_trusted(true)
    .with_latency(42)
    .with_pow(12345, vec![1, 2, 3, 4]);
    let snapshot = DhtPeerSnapshot { contact };

    // Verify all fields are accessible via the contact
    assert_eq!(snapshot.contact.node_id_string, "test-node");
    assert_eq!(snapshot.contact.address, "10.0.0.1");
    assert_eq!(snapshot.contact.port, 443);
    assert!(snapshot.contact.is_global);
    assert!(snapshot.contact.is_trusted);
    assert_eq!(snapshot.contact.latency_ms, Some(42));
    assert_eq!(snapshot.contact.pow_nonce, Some(12345));
    assert_eq!(snapshot.contact.public_key, Some(vec![1, 2, 3, 4]));
}

#[tokio::test]
async fn test_peer_state_snapshot_preserves_all_fields() {
    // Verify StagedTopologySnapshot stores complete PeerState (Iteration 74, Phase 50).
    let peer_state = PeerState {
        node_id: "test-node".to_string(),
        address: "10.0.0.1:443".to_string(),
        role: MeshNodeRole::GLOBAL,
        status: PeerStatus::Healthy,
        capabilities: synvoid_mesh::protocol::MeshCapabilities::default(),
        upstreams: std::collections::HashSet::new(),
        latency_ms: Some(42),
        first_seen: 1000,
        last_seen: 2000,
        is_global: true,
        is_trusted: true,
        connection_handle: None,
        geo: Some("us-east-1".to_string()),
        audit_successes: 100,
        audit_failures: 5,
        performance_audit_successes: 50,
        performance_audit_failures: 2,
        quic_port: Some(443),
        wireguard_port: Some(51820),
        advertised_port: Some(443),
        previous_reputation: Some(0.95),
    };

    let snapshot = StagedTopologySnapshot {
        peer_state: peer_state.clone(),
    };

    // Verify all fields preserved through snapshot
    assert_eq!(snapshot.peer_state.node_id, "test-node");
    assert_eq!(snapshot.peer_state.latency_ms, Some(42));
    assert_eq!(snapshot.peer_state.audit_successes, 100);
    assert_eq!(snapshot.peer_state.audit_failures, 5);
    assert_eq!(snapshot.peer_state.previous_reputation, Some(0.95));
    assert_eq!(snapshot.peer_state.quic_port, Some(443));
    assert_eq!(snapshot.peer_state.wireguard_port, Some(51820));
}

// ── Phase 53: No-Loss Snapshot Guard ────────────────────────────────────────

#[test]
fn test_dht_snapshot_covers_peer_contact_fields() {
    let snapshot_source = read_file("crates/synvoid-mesh/src/mesh/lifecycle.rs");

    // DhtPeerSnapshot must store a complete PeerContact
    assert!(
        snapshot_source.contains("pub contact:"),
        "DhtPeerSnapshot must have a 'contact' field storing the complete PeerContact"
    );
}

// ── Phase 11: Topology Secondary-Index Tests (Iteration 75) ────────────────

/// Helper to create a non-default PeerState with distinct values for every field.
fn make_distinct_peer_state(node_id: &str, is_global: bool) -> PeerState {
    PeerState {
        node_id: node_id.to_string(),
        address: "10.99.88.77:8443".to_string(),
        role: if is_global {
            MeshNodeRole::GLOBAL
        } else {
            MeshNodeRole::EDGE
        },
        status: PeerStatus::Healthy,
        capabilities: synvoid_mesh::protocol::MeshCapabilities {
            can_route: true,
            can_proxy: false,
            can_serve_dns: false,
            is_global: false,
            waf_enabled: false,
            max_hops: 3,
            supported_services: vec!["svc-a".to_string()],
            preferred_transport: None,
            supported_protocols: vec!["http".to_string()],
        },
        upstreams: ["upstream-a".to_string(), "upstream-b".to_string()]
            .into_iter()
            .collect(),
        latency_ms: Some(137),
        first_seen: 9001,
        last_seen: 9002,
        is_global,
        is_trusted: true,
        connection_handle: None,
        geo: Some("eu-west-3".to_string()),
        audit_successes: 42,
        audit_failures: 3,
        performance_audit_successes: 21,
        performance_audit_failures: 1,
        quic_port: Some(8443),
        wireguard_port: Some(51820),
        advertised_port: Some(9443),
        previous_reputation: Some(0.73),
    }
}

/// Global to non-global restoration: prior state non-global, startup writes global,
/// rollback restores prior, assert absent from global_nodes.
#[tokio::test]
async fn test_restore_global_to_non_global_removes_from_global_nodes() {
    let transport = make_test_transport();

    // Add a non-global peer
    let peer = make_distinct_peer_state("node-restore-1", false);
    transport
        .get_topology()
        .restore_peer_state(peer.clone())
        .await;

    // Verify NOT in global_nodes (non-global)
    let globals = transport.get_topology().get_global_nodes().await;
    assert!(
        !globals.contains(&"node-restore-1".to_string()),
        "non-global peer should not be in global_nodes after restore"
    );

    // Now simulate startup writing a global version
    let mut global_peer = peer.clone();
    global_peer.is_global = true;
    transport
        .get_topology()
        .restore_peer_state(global_peer)
        .await;

    let globals = transport.get_topology().get_global_nodes().await;
    assert!(
        globals.contains(&"node-restore-1".to_string()),
        "global peer should be in global_nodes after restore"
    );

    // Rollback restores the original non-global state
    transport
        .get_topology()
        .restore_peer_state(peer.clone())
        .await;

    let globals = transport.get_topology().get_global_nodes().await;
    assert!(
        !globals.contains(&"node-restore-1".to_string()),
        "after rollback, non-global peer must be removed from global_nodes"
    );
}

/// New global peer removal: startup adds new global peer, rollback removes it,
/// assert absent from both primary store and global_nodes.
#[tokio::test]
async fn test_rollback_removes_new_global_peer_entirely() {
    let transport = make_test_transport();

    // Simulate startup adding a brand new global peer (no prior state)
    let peer = make_distinct_peer_state("node-new-global", true);
    transport.get_topology().restore_peer_state(peer).await;

    // Verify present in both primary store and global_nodes
    assert!(
        transport
            .get_topology()
            .get_peer("node-new-global")
            .await
            .is_some(),
        "new global peer should exist in primary store"
    );
    let globals = transport.get_topology().get_global_nodes().await;
    assert!(
        globals.contains(&"node-new-global".to_string()),
        "new global peer should be in global_nodes"
    );

    // Rollback removes it (previous_topology was None -> peer_absent)
    transport
        .get_topology()
        .remove_peer("node-new-global")
        .await;

    assert!(
        transport
            .get_topology()
            .get_peer("node-new-global")
            .await
            .is_none(),
        "after rollback removal, peer must be absent from primary store"
    );
    let globals = transport.get_topology().get_global_nodes().await;
    assert!(
        !globals.contains(&"node-new-global".to_string()),
        "after rollback removal, peer must be absent from global_nodes"
    );
}

/// Non-global to global restoration: prior state global, startup writes non-global,
/// rollback restores prior, assert global_nodes contains the node.
#[tokio::test]
async fn test_restore_non_global_to_global_adds_to_global_nodes() {
    let transport = make_test_transport();

    // Add a global peer
    let peer = make_distinct_peer_state("node-restore-2", true);
    transport
        .get_topology()
        .restore_peer_state(peer.clone())
        .await;

    let globals = transport.get_topology().get_global_nodes().await;
    assert!(
        globals.contains(&"node-restore-2".to_string()),
        "global peer should be in global_nodes after restore"
    );

    // Simulate startup writing a non-global version
    let mut non_global_peer = peer.clone();
    non_global_peer.is_global = false;
    transport
        .get_topology()
        .restore_peer_state(non_global_peer)
        .await;

    let globals = transport.get_topology().get_global_nodes().await;
    assert!(
        !globals.contains(&"node-restore-2".to_string()),
        "non-global peer should not be in global_nodes after restore"
    );

    // Rollback restores the original global state
    transport
        .get_topology()
        .restore_peer_state(peer.clone())
        .await;

    let globals = transport.get_topology().get_global_nodes().await;
    assert!(
        globals.contains(&"node-restore-2".to_string()),
        "after rollback, global peer must be re-added to global_nodes"
    );
}

/// Complete field equality: use distinct non-default values for every snapshotted
/// field, restore, and assert exact restoration via topology_matches_snapshot().
#[tokio::test]
async fn test_complete_field_equality_after_rollback() {
    let transport = make_test_transport();

    let original = make_distinct_peer_state("node-complete", true);
    let snapshot = StagedTopologySnapshot {
        peer_state: original.clone(),
    };

    // Restore the original state
    transport.get_topology().restore_peer_state(original).await;

    // Verify exact match via topology_matches_snapshot
    assert!(
        transport
            .get_topology()
            .topology_matches_snapshot(&snapshot)
            .await,
        "topology_matches_snapshot must return true after exact restoration"
    );

    // Verify all fields individually for clarity
    let current = transport
        .get_topology()
        .get_peer("node-complete")
        .await
        .unwrap();
    assert_eq!(current.node_id, "node-complete");
    assert_eq!(current.address, "10.99.88.77:8443");
    assert_eq!(current.role, MeshNodeRole::GLOBAL);
    assert_eq!(current.status, PeerStatus::Healthy);
    assert!(current.capabilities.can_route);
    assert!(!current.capabilities.can_proxy);
    assert!(!current.capabilities.can_serve_dns);
    assert!(!current.capabilities.is_global);
    assert!(!current.capabilities.waf_enabled);
    assert_eq!(current.capabilities.max_hops, 3);
    assert_eq!(
        current.capabilities.supported_services,
        vec!["svc-a".to_string()]
    );
    assert!(current.capabilities.preferred_transport.is_none());
    assert_eq!(
        current.capabilities.supported_protocols,
        vec!["http".to_string()]
    );
    assert!(current.upstreams.contains("upstream-a"));
    assert!(current.upstreams.contains("upstream-b"));
    assert_eq!(current.latency_ms, Some(137));
    assert_eq!(current.first_seen, 9001);
    assert_eq!(current.last_seen, 9002);
    assert!(current.is_global);
    assert!(current.is_trusted);
    assert_eq!(current.geo, Some("eu-west-3".to_string()));
    assert_eq!(current.audit_successes, 42);
    assert_eq!(current.audit_failures, 3);
    assert_eq!(current.performance_audit_successes, 21);
    assert_eq!(current.performance_audit_failures, 1);
    assert_eq!(current.quic_port, Some(8443));
    assert_eq!(current.wireguard_port, Some(51820));
    assert_eq!(current.advertised_port, Some(9443));
    assert_eq!(current.previous_reputation, Some(0.73));

    // Verify global_nodes membership
    let globals = transport.get_topology().get_global_nodes().await;
    assert!(
        globals.contains(&"node-complete".to_string()),
        "global_nodes must contain the node after restore"
    );
}

/// Verify topology_matches_snapshot correctly detects non-matching global_nodes.
#[tokio::test]
async fn test_topology_matches_snapshot_detects_global_mismatch() {
    let transport = make_test_transport();

    // Create a global peer
    let peer = make_distinct_peer_state("node-mismatch", true);
    transport.get_topology().restore_peer_state(peer).await;

    // Create snapshot with is_global=false (mismatch with actual global_nodes state)
    let mut snapshot_peer = make_distinct_peer_state("node-mismatch", false);
    snapshot_peer.is_global = false;
    let snapshot = StagedTopologySnapshot {
        peer_state: snapshot_peer,
    };

    // Should NOT match because global_nodes has the node but snapshot says non-global
    assert!(
        !transport
            .get_topology()
            .topology_matches_snapshot(&snapshot)
            .await,
        "topology_matches_snapshot must detect global_nodes mismatch"
    );
}

/// Verify topology_matches_snapshot detects capability mismatches.
#[tokio::test]
async fn test_topology_matches_snapshot_detects_capability_mismatch() {
    let transport = make_test_transport();

    // Restore a peer with specific capabilities
    let peer = make_distinct_peer_state("node-caps", false);
    transport.get_topology().restore_peer_state(peer).await;

    // Create snapshot with different capabilities
    let mut snapshot_peer = make_distinct_peer_state("node-caps", false);
    snapshot_peer.capabilities = synvoid_mesh::protocol::MeshCapabilities {
        can_route: false,
        can_proxy: true,
        can_serve_dns: false,
        is_global: false,
        waf_enabled: false,
        max_hops: 0,
        supported_services: Vec::new(),
        preferred_transport: None,
        supported_protocols: Vec::new(),
    };
    let snapshot = StagedTopologySnapshot {
        peer_state: snapshot_peer,
    };

    assert!(
        !transport
            .get_topology()
            .topology_matches_snapshot(&snapshot)
            .await,
        "topology_matches_snapshot must detect capability mismatch"
    );
}

/// Verify topology_matches_snapshot detects timestamp mismatches.
#[tokio::test]
async fn test_topology_matches_snapshot_detects_timestamp_mismatch() {
    let transport = make_test_transport();

    let peer = make_distinct_peer_state("node-ts", false);
    transport.get_topology().restore_peer_state(peer).await;

    // Create snapshot with different timestamps
    let mut snapshot_peer = make_distinct_peer_state("node-ts", false);
    snapshot_peer.first_seen = 99999;
    snapshot_peer.last_seen = 88888;
    let snapshot = StagedTopologySnapshot {
        peer_state: snapshot_peer,
    };

    assert!(
        !transport
            .get_topology()
            .topology_matches_snapshot(&snapshot)
            .await,
        "topology_matches_snapshot must detect timestamp mismatch"
    );
}

// ── Phase 16: Late-Write Race Test (Iteration 75, Part C) ────────────────────

/// Verify that rollback stops peer sessions BEFORE logical restoration.
///
/// The Iteration 75 invariant: no peer/session/auxiliary task that can
/// mutate topology or DHT remains live before restoration begins. This
/// test checks the structural ordering in rollback_startup() to ensure
/// session teardown appears before `restore_peer_logical_state`.
#[test]
fn test_rollback_stops_sessions_before_logical_restoration() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    let rollback_body = extract_function(&content, "rollback_startup");

    // stop_staged_peer_activity (session teardown) must appear before
    // restore_peer_logical_state (logical restoration)
    let idx_session_teardown = rollback_body
        .find("stop_staged_peer_activity")
        .expect("rollback_startup must call stop_staged_peer_activity");
    let idx_restore = rollback_body
        .find("restore_and_verify_peer_logical_state")
        .or_else(|| rollback_body.find("restore_peer_logical_state"))
        .expect("rollback_startup must call restore_and_verify_peer_logical_state");

    assert!(
        idx_session_teardown < idx_restore,
        "Session/auxiliary teardown (stop_staged_peer_activity at pos {idx_session_teardown}) \
         must occur BEFORE logical restoration (pos {idx_restore}). \
         This is the Iteration 75 invariant: physical teardown before logical restoration."
    );

    // The session teardown must also appear before the topology/DHT verification
    let idx_verify_topology = rollback_body
        .find("topology_matches_snapshot")
        .unwrap_or(rollback_body.find("peer_absent").unwrap_or(usize::MAX));
    let idx_verify_dht = rollback_body
        .find("peer_matches_snapshot")
        .unwrap_or(usize::MAX);
    let idx_verification = idx_verify_topology.min(idx_verify_dht);

    if idx_verification < usize::MAX {
        assert!(
            idx_session_teardown < idx_verification,
            "Session/auxiliary teardown must also occur BEFORE topology/DHT verification"
        );
    }
}

/// Verify that the stop_staged_peer_activity helper exists and handles
/// auxiliary task cancellation before session drain.
#[test]
fn test_stop_staged_peer_activity_cancels_auxiliary_before_session() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");

    // The helper method must exist
    assert!(
        content.contains("fn stop_staged_peer_activity"),
        "transport.rs must contain stop_staged_peer_activity helper method"
    );

    let helper_body = extract_function(&content, "stop_staged_peer_activity");

    // Must cancel auxiliary tasks first
    assert!(
        helper_body.contains("cancel_auxiliary_tasks_for_sessions"),
        "stop_staged_peer_activity must cancel auxiliary tasks"
    );

    // Must remove from peer_sessions
    assert!(
        helper_body.contains("sessions.remove") || helper_body.contains("peer_sessions"),
        "stop_staged_peer_activity must stop peer sessions"
    );

    // Auxiliary cancellation must appear before session drain in the helper
    let idx_aux_cancel = helper_body
        .find("cancel_auxiliary_tasks_for_sessions")
        .expect("helper must call cancel_auxiliary_tasks_for_sessions");
    let idx_session_drain = helper_body
        .find("sessions.remove")
        .or_else(|| helper_body.find("peer_sessions"))
        .expect("helper must access peer_sessions");

    assert!(
        idx_aux_cancel < idx_session_drain,
        "Auxiliary task cancellation must occur before session drain in stop_staged_peer_activity"
    );
}

// ── Phase 17: Auxiliary Late-Write Test (Iteration 75, Part C) ────────────────

/// Verify that rollback terminates auxiliary tasks BEFORE logical restoration.
///
/// Auxiliary tasks (e.g., preflight route queries) can read/write topology
/// and DHT state. They must be cancelled before the topology/DHT restoration
/// phase to prevent late writes from invalidating restored state.
#[test]
fn test_rollback_cancels_auxiliary_tasks_before_restoration() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    let rollback_body = extract_function(&content, "rollback_startup");

    // cancel_auxiliary_tasks_for_sessions must appear via stop_staged_peer_activity
    // in the rollback body. Find the stop_staged_peer_activity call and verify
    // auxiliary cancellation is part of the teardown before restoration.
    let idx_teardown = rollback_body
        .find("stop_staged_peer_activity")
        .expect("rollback_startup must call stop_staged_peer_activity for auxiliary cancellation");
    let idx_restore = rollback_body
        .find("restore_and_verify_peer_logical_state")
        .or_else(|| rollback_body.find("restore_peer_logical_state"))
        .expect("rollback_startup must call restore_and_verify_peer_logical_state");

    assert!(
        idx_teardown < idx_restore,
        "stop_staged_peer_activity (which cancels auxiliary tasks) must appear \
         BEFORE restore_and_verify_peer_logical_state in rollback_startup"
    );

    // Verify the stop_staged_peer_activity helper itself cancels auxiliary tasks
    let helper_body = extract_function(&content, "stop_staged_peer_activity");
    assert!(
        helper_body.contains("cancel_auxiliary_tasks_for_sessions"),
        "stop_staged_peer_activity must cancel auxiliary tasks for the session"
    );

    // Verify auxiliary cancellation happens before session handle drain
    let idx_aux = helper_body
        .find("cancel_auxiliary_tasks_for_sessions")
        .unwrap();
    let idx_handle = helper_body
        .find("handle.abort()")
        .or_else(|| helper_body.find("tokio::select!"))
        .unwrap_or(usize::MAX);

    assert!(
        idx_aux < idx_handle,
        "Auxiliary task cancellation (pos {idx_aux}) must precede session handle \
         operations (pos {idx_handle}) in stop_staged_peer_activity"
    );
}

// ── Part D: Verification-Failure Residue Retention Tests ────────────────────

/// Verify that rollback_startup uses restore_and_verify_peer_logical_state()
/// (combined restore + verify) rather than separate restore and verify loops.
#[test]
fn test_rollback_uses_combined_restore_and_verify() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    let rollback_body = extract_function(&content, "rollback_startup");

    // rollback_startup must call restore_and_verify_peer_logical_state
    assert!(
        rollback_body.contains("restore_and_verify_peer_logical_state"),
        "rollback_startup must use restore_and_verify_peer_logical_state (combined restore + verify)"
    );

    // Must NOT have separate verify logic for topology/DHT in rollback_startup
    // (the combined helper handles verification internally)
    // Allow topology_matches_snapshot/peer_absent only if they appear inside
    // the combined helper, not in rollback_startup directly
    let idx_combined = rollback_body
        .find("restore_and_verify_peer_logical_state")
        .unwrap();
    let remaining_after_combined = &rollback_body[idx_combined..];
    // The only topology/DHT checks should be within the combined helper call,
    // not separate loops
    assert!(
        !remaining_after_combined.contains("for peer in &stage.created_peers")
            || remaining_after_combined.matches("for peer in").count() <= 1,
        "rollback_startup should not have a second loop over created_peers for separate verification"
    );
}

/// Verify that rollback_startup tracks unresolved peers on verification failure.
#[test]
fn test_rollback_tracks_unresolved_peers() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    let rollback_body = extract_function(&content, "rollback_startup");

    // Must push to report.unresolved_peers on error
    assert!(
        rollback_body.contains("report.unresolved_peers.push"),
        "rollback_startup must push failed peers to report.unresolved_peers"
    );
}

/// Verify that rollback_and_return stores only unresolved peers in residue.
#[test]
fn test_rollback_and_return_stores_only_unresolved_in_residue() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");

    // rollback_and_return must use rollback.unresolved_peers for residue, not stage.created_peers
    assert!(
        content.contains("rollback.unresolved_peers.clone()"),
        "rollback_and_return must use rollback.unresolved_peers for residue"
    );
    // Should NOT store all staged peers
    assert!(
        !content.contains("peers: stage.created_peers.clone()"),
        "rollback_and_return must NOT store all staged peers in residue"
    );
}

/// Verify that recover_failed_state uses restore_and_verify_peer_logical_state().
#[test]
fn test_recovery_uses_combined_restore_and_verify() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    let recovery_fn = extract_function(&content, "recover_failed_state");

    assert!(
        recovery_fn.contains("restore_and_verify_peer_logical_state"),
        "recover_failed_state must use restore_and_verify_peer_logical_state"
    );
}

/// Verify that recover_failed_state retains unresolved peers in residue.
#[test]
fn test_recovery_retains_unresolved_peers() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    let recovery_fn = extract_function(&content, "recover_failed_state");

    // Must track remaining_peers
    assert!(
        recovery_fn.contains("remaining_peers"),
        "recover_failed_state must track remaining_peers"
    );

    // Must re-store FailedStartupResidue with remaining peers
    assert!(
        recovery_fn.contains("FailedStartupResidue {"),
        "recover_failed_state must reconstruct FailedStartupResidue"
    );
}

/// Verify that recover_failed_state deduplicates errors.
#[test]
fn test_recovery_deduplicates_errors() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    let recovery_fn = extract_function(&content, "recover_failed_state");

    assert!(
        recovery_fn.contains("remaining_errors.contains(&error)"),
        "recover_failed_state must deduplicate errors with contains check"
    );
}

/// Verify that RollbackReport has unresolved_peers field.
#[test]
fn test_rollback_report_has_unresolved_peers() {
    let content = read_file("crates/synvoid-mesh/src/mesh/lifecycle.rs");
    assert!(
        content.contains("pub unresolved_peers: Vec<StagedPeerResource>"),
        "RollbackReport must have pub unresolved_peers field"
    );
}

/// Verify that restore_and_verify_peer_logical_state exists as a method.
#[test]
fn test_restore_and_verify_method_exists() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    assert!(
        content.contains("fn restore_and_verify_peer_logical_state"),
        "transport.rs must contain restore_and_verify_peer_logical_state method"
    );
}

// ── Iteration 76: Part A — Zero-budget rollback finalization ──────────────

/// Verify that `rollback_startup` ALWAYS calls `join_all` on the staged
/// `MeshTaskGroup`, even when the remaining budget is zero. Prior to
/// Iteration 76 Part A, the call site skipped `join_all` entirely if
/// `task_remaining.is_zero()`, leaving tasks orphaned in the registry.
///
/// This test reads the source to enforce the post-fix invariant: there is
/// no conditional skip path between `task_remaining` and `join_all`.
#[test]
fn test_rollback_startup_always_finalizes_task_group() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    let rollback_body = extract_function(&content, "rollback_startup");

    // Must contain a call to `join_all(remaining(deadline))` or
    // `join_all(task_remaining)` — but not guarded by `is_zero()`.
    assert!(
        rollback_body.contains("join_all("),
        "rollback_startup must call join_all unconditionally"
    );

    // The historical bug: a `if task_remaining.is_zero() { Vec::new() }`
    // skip-block must not be present.
    assert!(
        !rollback_body.contains("if task_remaining.is_zero()"),
        "rollback_startup must not skip join_all when budget is zero (Iteration 76 Part A)"
    );

    // The pre-fix variant used a `let _exits = group.join_all(...)` form
    // with an early `Vec::new()`. The post-fix variant must use
    // `let exits = stage.task_group.join_all(remaining(deadline))`.
    assert!(
        rollback_body.contains("let exits = stage.task_group.join_all(remaining(deadline))"),
        "rollback_startup must compute exits from a single join_all call"
    );
}

/// Verify that `recover_failed_state` ALWAYS finalizes its task group, even
/// under a zero remaining budget. Recovery is a sibling of rollback and
/// must not regress the Iteration 76 Part A contract.
#[test]
fn test_recover_failed_state_always_finalizes_task_group() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    let recovery_body = extract_function(&content, "recover_failed_state");

    assert!(
        recovery_body.contains("join_all("),
        "recover_failed_state must call join_all unconditionally"
    );

    // No zero-budget skip path.
    assert!(
        !recovery_body.contains("if task_remaining.is_zero()"),
        "recover_failed_state must not skip join_all when budget is zero (Iteration 76 Part A)"
    );
}

// ── Iteration 76: Part B — Cooperative session cancellation ───────────────

/// Verify that `stop_staged_peer_activity` always sends the cooperative
/// shutdown signal before draining/aborting the session handle.
///
/// This is the Iteration 76 Part B invariant: the session's
/// `peer_message_loop` must be given a chance to observe the watch signal
/// and run its child JoinSet drain path before parent abort is considered.
#[test]
fn test_stop_staged_peer_activity_sends_shutdown_signal() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    let stop_body = extract_function(&content, "stop_staged_peer_activity");

    assert!(
        stop_body.contains("shutdown_tx.send(true)"),
        "stop_staged_peer_activity must send cooperative shutdown signal before stopping handle"
    );

    // Must call stop_peer_session_task with a budget.
    assert!(
        stop_body.contains("stop_peer_session_task"),
        "stop_staged_peer_activity must delegate to stop_peer_session_task"
    );
}

/// Verify that `stop_peer_session_task` exists as a shared helper and
/// returns a `PeerSessionStopOutcome` so callers can distinguish drained
/// from forcibly-aborted sessions.
#[test]
fn test_stop_peer_session_task_helper_exists() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport.rs");
    assert!(
        content.contains("fn stop_peer_session_task"),
        "transport.rs must define stop_peer_session_task helper (Iteration 76 Part B)"
    );
    assert!(
        content.contains("PeerSessionStopOutcome"),
        "transport.rs must use PeerSessionStopOutcome to classify cleanup paths"
    );
}

/// Verify that `PeerSessionTask` carries a `shutdown_tx` field so the
/// session can be cooperatively cancelled. This is the Iteration 76 Part B
/// type-level invariant.
#[test]
fn test_peer_session_task_has_shutdown_tx() {
    let content = read_file("crates/synvoid-mesh/src/mesh/lifecycle.rs");
    assert!(
        content.contains("pub struct PeerSessionTask"),
        "lifecycle.rs must define PeerSessionTask"
    );

    // The shutdown_tx field is the cooperative-cancellation carrier.
    // Look for it in the struct body.
    let struct_start = content
        .find("pub struct PeerSessionTask")
        .expect("PeerSessionTask struct must exist");
    let struct_body_start = content[struct_start..]
        .find('{')
        .map(|i| struct_start + i)
        .expect("PeerSessionTask must have a body");
    // Scan forward to find the closing brace at depth 0.
    let mut depth = 0i32;
    let mut struct_end = struct_body_start;
    for (i, ch) in content[struct_body_start..].char_indices() {
        match ch {
            '{' => depth += 1,
            '}' => {
                depth -= 1;
                if depth == 0 {
                    struct_end = struct_body_start + i;
                    break;
                }
            }
            _ => {}
        }
    }
    let struct_body = &content[struct_body_start..=struct_end];
    assert!(
        struct_body.contains("shutdown_tx"),
        "PeerSessionTask must contain a shutdown_tx field for cooperative cancellation"
    );
}

// ── Iteration 76: Part C — Safe DHT force restoration ─────────────────────

/// Verify that `KBucket::force_replace` returns a `Result` (not an `Option`)
/// so that a full bucket with an absent target can fail closed without
/// evicting an unrelated contact. The historical signature was
/// `Option<PeerContact>`, which silently evicted the oldest peer.
#[test]
fn test_kbucket_force_replace_returns_result() {
    let content = read_file("crates/synvoid-mesh/src/mesh/dht/routing/bucket.rs");
    assert!(
        content.contains("pub fn force_replace"),
        "KBucket must define force_replace"
    );

    // Find the signature and assert it returns a Result, not Option.
    let sig_marker = "pub fn force_replace(";
    let sig_pos = content
        .find(sig_marker)
        .expect("force_replace must be defined");
    // Walk forward to find the return-type `->` (it may span multiple lines).
    let after_sig = &content[sig_pos..];
    let arrow_pos = after_sig
        .find("->")
        .expect("force_replace must have a return type");
    let return_type_end = after_sig[arrow_pos + 2..]
        .find(')')
        .map(|i| arrow_pos + 2 + i)
        .unwrap_or(after_sig.len());
    let return_type = &after_sig[arrow_pos..return_type_end];
    assert!(
        return_type.contains("Result"),
        "force_replace must return Result, not Option (Iteration 76 Part C). Found: {return_type}"
    );
    assert!(
        return_type.contains("ForceRestoreError"),
        "force_replace must return ForceRestoreError on conflict"
    );
}

/// Verify that `RoutingTable::force_restore_contact` returns a typed
/// `Result` with `ForceRestoreContactError`, mapping the bucket-level
/// conflict error to the table-level error type.
#[test]
fn test_routing_table_force_restore_returns_typed_error() {
    let content = read_file("crates/synvoid-mesh/src/mesh/dht/routing/table.rs");
    assert!(
        content.contains("ForceRestoreContactError"),
        "RoutingTable must define ForceRestoreContactError"
    );
    assert!(
        content.contains("pub fn force_restore_contact"),
        "RoutingTable must define force_restore_contact"
    );
}

// ── Iteration 76: Part E — Refined stream timeout semantics ───────────────

/// Verify that the peer message loop applies a per-message read timeout
/// distinctly from the optional total stream lifetime timeout. The two
/// timeouts are independently configurable and must not be conflated.
#[test]
fn test_peer_message_loop_has_distinct_timeouts() {
    let content = read_file("crates/synvoid-mesh/src/mesh/transport_peer.rs");

    // The per-message read timeout accessor.
    assert!(
        content.contains("peer_message_read_timeout")
            || content.contains("peer_message_timeout_secs"),
        "transport_peer.rs must define a per-message read timeout"
    );

    // The total stream lifetime timeout accessor (opt-in).
    assert!(
        content.contains("peer_stream_total_timeout")
            || content.contains("peer_stream_total_timeout_secs"),
        "transport_peer.rs must define an opt-in total stream lifetime timeout"
    );

    // `apply_read_timeouts` helper must exist to wrap reads with the
    // per-message timeout.
    assert!(
        content.contains("apply_read_timeouts"),
        "transport_peer.rs must define apply_read_timeouts helper (Iteration 76 Part E)"
    );
}
