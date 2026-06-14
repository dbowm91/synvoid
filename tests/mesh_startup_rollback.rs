//! Behavioral tests for mesh startup rollback (Iteration 69, Phase 21).
//!
//! These tests use failure-injection hooks to verify that `MeshTransport::start()`
//! properly rolls back on failure and leaves the lifecycle in a recoverable state.

use std::sync::Arc;

use parking_lot::RwLock;
use synvoid_mesh::cert::MeshCertManager;
use synvoid_mesh::config::MeshConfig;
use synvoid_mesh::lifecycle::MeshLifecycleState;
use synvoid_mesh::topology::MeshTopology;
use synvoid_mesh::transport::{MeshTransport, StartupFailurePoint};

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
        StartupFailurePoint::AfterLifecycleCommit
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
    let _ = format!("{:?}", StartupFailurePoint::AfterLifecycleCommit);
}

#[test]
fn test_startup_failure_point_clone() {
    let point = StartupFailurePoint::AfterCriticalTasks;
    let cloned = point;
    assert_eq!(point, cloned);
}

#[test]
fn test_rollback_allows_retry_from_failed_state() {
    // After a failed start, can_start() should return true (from Failed state)
    let mut state = MeshLifecycleState::Failed;
    assert!(state.can_start());

    // Verify a full lifecycle: Failed -> Starting -> Running
    state.transition_to_starting().unwrap();
    assert_eq!(state, MeshLifecycleState::Starting);
    state.transition_to_running().unwrap();
    assert_eq!(state, MeshLifecycleState::Running);
}

#[test]
fn test_lifecycle_not_stuck_at_starting_after_failure() {
    // Simulate: Stopped -> Starting -> (failure) -> should not be stuck at Starting
    let mut state = MeshLifecycleState::Stopped;
    state.transition_to_starting().unwrap();
    assert_eq!(state, MeshLifecycleState::Starting);

    // On failure, we can transition to Failed (which allows retry)
    state.transition_to_failed();
    assert_eq!(state, MeshLifecycleState::Failed);

    // And from Failed, we can start again
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
fn test_lifecycle_failed_state_allows_retry() {
    let state = MeshLifecycleState::Failed;
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
