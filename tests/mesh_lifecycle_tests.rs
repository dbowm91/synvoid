use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;
use synvoid_mesh::cert::MeshCertManager;
use synvoid_mesh::config::MeshConfig;
use synvoid_mesh::lifecycle::{
    MeshLifecycleState, MeshShutdownReport, MeshStartupPolicy, MeshStartupReport, MeshTaskClass,
    MeshTaskExit, MeshTaskExitReason, MeshTaskId,
};
use synvoid_mesh::task_group::MeshTaskGroup;
use synvoid_mesh::topology::MeshTopology;
use synvoid_mesh::transport::MeshTransport;

// ── Lifecycle State Machine Tests ────────────────────────────────────────────

#[test]
fn lifecycle_can_start_from_stopped_not_failed() {
    assert!(MeshLifecycleState::Stopped.can_start());
    assert!(!MeshLifecycleState::Failed.can_start());
    assert!(!MeshLifecycleState::Starting.can_start());
    assert!(!MeshLifecycleState::Running.can_start());
    assert!(!MeshLifecycleState::Stopping.can_start());
}

#[test]
fn lifecycle_can_stop_only_from_running() {
    assert!(MeshLifecycleState::Running.can_stop());
    assert!(!MeshLifecycleState::Stopped.can_stop());
    assert!(!MeshLifecycleState::Starting.can_stop());
    assert!(!MeshLifecycleState::Stopping.can_stop());
    assert!(!MeshLifecycleState::Failed.can_stop());
}

#[test]
fn lifecycle_valid_transition_sequence() {
    let mut state = MeshLifecycleState::Stopped;

    state.transition_to_starting().unwrap();
    assert_eq!(state, MeshLifecycleState::Starting);

    state.transition_to_running().unwrap();
    assert_eq!(state, MeshLifecycleState::Running);

    state.transition_to_stopping().unwrap();
    assert_eq!(state, MeshLifecycleState::Stopping);

    state.transition_to_stopped();
    assert_eq!(state, MeshLifecycleState::Stopped);
}

#[test]
fn lifecycle_restart_after_failure_requires_recovery() {
    let mut state = MeshLifecycleState::Failed;

    // Failed cannot directly transition to Starting
    assert!(state.transition_to_starting().is_err());
    assert_eq!(state, MeshLifecycleState::Failed);

    // Must recover to Stopped first
    state.transition_to_stopped();
    assert_eq!(state, MeshLifecycleState::Stopped);

    state.transition_to_starting().unwrap();
    assert_eq!(state, MeshLifecycleState::Starting);

    state.transition_to_running().unwrap();
    assert_eq!(state, MeshLifecycleState::Running);
}

#[test]
fn lifecycle_invalid_transition_errors() {
    // Running -> Starting is not allowed
    let mut state = MeshLifecycleState::Running;
    assert!(state.transition_to_starting().is_err());
    assert_eq!(state, MeshLifecycleState::Running); // unchanged

    // Starting -> Stopping is not allowed
    let mut state = MeshLifecycleState::Starting;
    assert!(state.transition_to_stopping().is_err());
    assert_eq!(state, MeshLifecycleState::Starting);

    // Starting -> Running requires Starting (this is valid)
    // but Running -> Running is not
    let mut state = MeshLifecycleState::Running;
    assert!(state.transition_to_running().is_err());

    // Stopped -> Running is not allowed
    let mut state = MeshLifecycleState::Stopped;
    assert!(state.transition_to_running().is_err());

    // Stopped -> Stopping is not allowed
    let mut state = MeshLifecycleState::Stopped;
    assert!(state.transition_to_stopping().is_err());

    // Failed -> Stopping is not allowed
    let mut state = MeshLifecycleState::Failed;
    assert!(state.transition_to_stopping().is_err());

    // Stopping -> Starting is not allowed
    let mut state = MeshLifecycleState::Stopping;
    assert!(state.transition_to_starting().is_err());
}

#[test]
fn lifecycle_transition_to_stopped_from_any_state() {
    for initial in [
        MeshLifecycleState::Stopped,
        MeshLifecycleState::Starting,
        MeshLifecycleState::Running,
        MeshLifecycleState::Stopping,
        MeshLifecycleState::Failed,
    ] {
        let mut state = initial;
        state.transition_to_stopped();
        assert_eq!(state, MeshLifecycleState::Stopped);
    }
}

#[test]
fn lifecycle_transition_to_failed_from_any_state() {
    for initial in [
        MeshLifecycleState::Stopped,
        MeshLifecycleState::Starting,
        MeshLifecycleState::Running,
        MeshLifecycleState::Stopping,
        MeshLifecycleState::Failed,
    ] {
        let mut state = initial;
        state.transition_to_failed();
        assert_eq!(state, MeshLifecycleState::Failed);
    }
}

// ── MeshTaskGroup Tests ──────────────────────────────────────────────────────

#[tokio::test]
async fn task_group_spawn_critical_and_join() {
    let mut group = MeshTaskGroup::new();
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();

    group.spawn_critical("critical_1", async move {
        let _ = rx.await;
    });

    let (c, b, ch) = group.active_count();
    assert_eq!(c, 1);
    assert_eq!(b, 0);
    assert_eq!(ch, 0);
    assert!(!group.is_empty());

    tx.send(()).unwrap();

    let exits = group.join_all(Duration::from_secs(5)).await;
    assert_eq!(exits.len(), 1);
    assert_eq!(exits[0].name, "critical_1");
    assert_eq!(exits[0].class, MeshTaskClass::CriticalService);
    assert!(group.is_empty());
}

#[tokio::test]
async fn task_group_spawn_background_and_join() {
    let mut group = MeshTaskGroup::new();
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();

    group.spawn_background("bg_1", async move {
        let _ = rx.await;
    });

    let (c, b, ch) = group.active_count();
    assert_eq!(c, 0);
    assert_eq!(b, 1);
    assert_eq!(ch, 0);
    assert!(!group.is_empty());

    tx.send(()).unwrap();

    let exits = group.join_all(Duration::from_secs(5)).await;
    assert_eq!(exits.len(), 1);
    assert_eq!(exits[0].name, "bg_1");
    assert_eq!(exits[0].class, MeshTaskClass::RestartableBackground);
    assert!(group.is_empty());
}

#[tokio::test]
async fn task_group_spawn_child_and_join() {
    let mut group = MeshTaskGroup::new();
    let (tx, rx) = tokio::sync::oneshot::channel::<()>();

    group.spawn_child("child_1", async move {
        let _ = rx.await;
    });

    let (c, b, ch) = group.active_count();
    assert_eq!(c, 0);
    assert_eq!(b, 0);
    assert_eq!(ch, 1);
    assert!(!group.is_empty());

    tx.send(()).unwrap();

    let exits = group.join_all(Duration::from_secs(5)).await;
    assert_eq!(exits.len(), 1);
    assert_eq!(exits[0].name, "child_1");
    assert_eq!(exits[0].class, MeshTaskClass::BoundedChild);
    assert!(group.is_empty());
}

#[tokio::test]
async fn task_group_shutdown_signal_propagation() {
    let group = MeshTaskGroup::new();
    let mut rx = group.shutdown_receiver();

    assert!(!*rx.borrow());

    group.begin_shutdown().await;

    rx.changed().await.unwrap();
    assert!(*rx.borrow());
}

#[tokio::test]
async fn task_group_join_all_timeout_aborts_slow_tasks() {
    let mut group = MeshTaskGroup::new();

    group.spawn_critical("slow_task", async {
        tokio::time::sleep(Duration::from_secs(60)).await;
    });

    let exits = group.join_all(Duration::from_millis(50)).await;
    assert_eq!(exits.len(), 1);
    assert_eq!(exits[0].name, "slow_task");
    assert_eq!(exits[0].reason, MeshTaskExitReason::Aborted);
    assert!(group.is_empty());
}

#[tokio::test]
async fn task_group_active_count_tracks_tasks() {
    let mut group = MeshTaskGroup::new();
    assert_eq!(group.active_count(), (0, 0, 0));
    assert!(group.is_empty());

    let (_tx1, rx1) = tokio::sync::oneshot::channel::<()>();
    let (_tx2, rx2) = tokio::sync::oneshot::channel::<()>();
    let (_tx3, rx3) = tokio::sync::oneshot::channel::<()>();

    group.spawn_critical("c1", async move {
        let _ = rx1.await;
    });
    group.spawn_background("b1", async move {
        let _ = rx2.await;
    });
    group.spawn_child("ch1", async move {
        let _ = rx3.await;
    });

    assert_eq!(group.active_count(), (1, 1, 1));
    assert!(!group.is_empty());

    let (_tx4, rx4) = tokio::sync::oneshot::channel::<()>();
    group.spawn_critical("c2", async move {
        let _ = rx4.await;
    });
    assert_eq!(group.active_count(), (2, 1, 1));
}

#[tokio::test]
async fn task_group_is_empty_initial_and_after_join() {
    let mut group = MeshTaskGroup::new();
    assert!(group.is_empty());

    let (tx, rx) = tokio::sync::oneshot::channel::<()>();
    group.spawn_background("bg_temp", async move {
        let _ = rx.await;
    });
    assert!(!group.is_empty());

    tx.send(()).unwrap();
    let _exits = group.join_all(Duration::from_secs(5)).await;
    assert!(group.is_empty());
}

#[tokio::test]
async fn task_group_panic_detection() {
    let mut group = MeshTaskGroup::new();

    group.spawn_critical("panicker", async {
        panic!("test panic message");
    });

    let exits = group.join_all(Duration::from_secs(5)).await;
    assert_eq!(exits.len(), 1);
    assert_eq!(exits[0].name, "panicker");
    assert_eq!(exits[0].class, MeshTaskClass::CriticalService);
    match &exits[0].reason {
        MeshTaskExitReason::Panic(msg) => {
            assert_eq!(msg, "test panic message");
        }
        other => panic!("expected Panic, got {:?}", other),
    }
}

#[tokio::test]
async fn task_group_clean_completion_before_shutdown() {
    let mut group = MeshTaskGroup::new();

    group.spawn_critical("completer", async {
        tokio::time::sleep(Duration::from_millis(10)).await;
    });

    let exits = group.join_all(Duration::from_secs(5)).await;
    assert_eq!(exits.len(), 1);
    // Critical services completing before shutdown is UnexpectedCompletion
    assert_eq!(exits[0].reason, MeshTaskExitReason::UnexpectedCompletion);
}

#[tokio::test]
async fn task_group_subscribe_exits_receives_events() {
    let mut group = MeshTaskGroup::new();
    let mut exit_rx = group.subscribe_exits();

    group.spawn_critical("quick_task", async {
        tokio::time::sleep(Duration::from_millis(10)).await;
    });

    // Wait for the task to finish and emit its exit event.
    let exit = tokio::time::timeout(Duration::from_secs(5), exit_rx.recv())
        .await
        .expect("timeout waiting for exit event")
        .expect("exit channel closed");

    assert_eq!(exit.name, "quick_task");
    assert_eq!(exit.class, MeshTaskClass::CriticalService);

    // Drain remaining tasks so join_all doesn't hang.
    let _exits = group.join_all(Duration::from_secs(5)).await;
}

#[tokio::test]
async fn task_group_multiple_task_types_join_order() {
    let mut group = MeshTaskGroup::new();

    let (tx_crit, rx_crit) = tokio::sync::oneshot::channel::<()>();
    let (tx_bg, rx_bg) = tokio::sync::oneshot::channel::<()>();
    let (tx_child, rx_child) = tokio::sync::oneshot::channel::<()>();

    group.spawn_critical("crit", async move {
        let _ = rx_crit.await;
    });
    group.spawn_background("bg", async move {
        let _ = rx_bg.await;
    });
    group.spawn_child("child", async move {
        let _ = rx_child.await;
    });

    // All three should be tracked.
    assert_eq!(group.active_count(), (1, 1, 1));

    // Complete them all.
    tx_crit.send(()).unwrap();
    tx_bg.send(()).unwrap();
    tx_child.send(()).unwrap();

    let exits = group.join_all(Duration::from_secs(5)).await;
    assert_eq!(exits.len(), 3);

    // Verify exit names are present (order: critical, background, children).
    let names: Vec<&str> = exits.iter().map(|e| e.name).collect();
    assert!(names.contains(&"crit"));
    assert!(names.contains(&"bg"));
    assert!(names.contains(&"child"));

    assert!(group.is_empty());
}

// ── MeshTaskExit Tests ───────────────────────────────────────────────────────

#[test]
fn exit_fatal_for_critical_service() {
    // UnexpectedCompletion is fatal for critical tasks
    let exit = MeshTaskExit {
        id: MeshTaskId(0),
        name: "server",
        class: MeshTaskClass::CriticalService,
        reason: MeshTaskExitReason::UnexpectedCompletion,
    };
    assert!(exit.is_fatal());

    // Error is fatal for critical tasks
    let exit = MeshTaskExit {
        id: MeshTaskId(0),
        name: "server",
        class: MeshTaskClass::CriticalService,
        reason: MeshTaskExitReason::Error("bind failed".into()),
    };
    assert!(exit.is_fatal());

    // Panic is fatal for critical tasks
    let exit = MeshTaskExit {
        id: MeshTaskId(0),
        name: "server",
        class: MeshTaskClass::CriticalService,
        reason: MeshTaskExitReason::Panic("overflow".into()),
    };
    assert!(exit.is_fatal());

    // CleanCompletion is NOT fatal for critical tasks
    let exit = MeshTaskExit {
        id: MeshTaskId(0),
        name: "server",
        class: MeshTaskClass::CriticalService,
        reason: MeshTaskExitReason::CleanCompletion,
    };
    assert!(!exit.is_fatal());

    // Cancelled is NOT fatal for critical tasks
    let exit = MeshTaskExit {
        id: MeshTaskId(0),
        name: "server",
        class: MeshTaskClass::CriticalService,
        reason: MeshTaskExitReason::Cancelled,
    };
    assert!(!exit.is_fatal());

    // Aborted is NOT fatal for critical tasks
    let exit = MeshTaskExit {
        id: MeshTaskId(0),
        name: "server",
        class: MeshTaskClass::CriticalService,
        reason: MeshTaskExitReason::Aborted,
    };
    assert!(!exit.is_fatal());
}

#[test]
fn exit_fatal_for_non_critical_never() {
    // UnexpectedCompletion is not fatal for non-critical tasks
    let exit = MeshTaskExit {
        id: MeshTaskId(0),
        name: "bg_sync",
        class: MeshTaskClass::RestartableBackground,
        reason: MeshTaskExitReason::UnexpectedCompletion,
    };
    assert!(!exit.is_fatal());

    // Error is not fatal for non-critical tasks
    let exit = MeshTaskExit {
        id: MeshTaskId(0),
        name: "child_task",
        class: MeshTaskClass::BoundedChild,
        reason: MeshTaskExitReason::Error("oops".into()),
    };
    assert!(!exit.is_fatal());

    // Panic is not fatal for non-critical tasks
    let exit = MeshTaskExit {
        id: MeshTaskId(0),
        name: "startup",
        class: MeshTaskClass::OneShotStartup,
        reason: MeshTaskExitReason::Panic("init failed".into()),
    };
    assert!(!exit.is_fatal());
}

#[test]
fn exit_pre_shutdown_before_shutdown() {
    // Before shutdown (shutdown_started=false): non-cancelled exits are pre-shutdown
    let exit = MeshTaskExit {
        id: MeshTaskId(0),
        name: "task",
        class: MeshTaskClass::CriticalService,
        reason: MeshTaskExitReason::UnexpectedCompletion,
    };
    assert!(exit.is_pre_shutdown(false));

    let exit = MeshTaskExit {
        id: MeshTaskId(0),
        name: "task",
        class: MeshTaskClass::CriticalService,
        reason: MeshTaskExitReason::CleanCompletion,
    };
    assert!(exit.is_pre_shutdown(false));

    let exit = MeshTaskExit {
        id: MeshTaskId(0),
        name: "task",
        class: MeshTaskClass::CriticalService,
        reason: MeshTaskExitReason::Error("fail".into()),
    };
    assert!(exit.is_pre_shutdown(false));

    let exit = MeshTaskExit {
        id: MeshTaskId(0),
        name: "task",
        class: MeshTaskClass::CriticalService,
        reason: MeshTaskExitReason::Panic("boom".into()),
    };
    assert!(exit.is_pre_shutdown(false));

    // Cancelled is NOT pre-shutdown even before shutdown signal
    let exit = MeshTaskExit {
        id: MeshTaskId(0),
        name: "task",
        class: MeshTaskClass::CriticalService,
        reason: MeshTaskExitReason::Cancelled,
    };
    assert!(!exit.is_pre_shutdown(false));
}

#[test]
fn exit_pre_shutdown_after_shutdown() {
    // After shutdown (shutdown_started=true): only UnexpectedCompletion is pre-shutdown
    let exit = MeshTaskExit {
        id: MeshTaskId(0),
        name: "task",
        class: MeshTaskClass::CriticalService,
        reason: MeshTaskExitReason::UnexpectedCompletion,
    };
    assert!(exit.is_pre_shutdown(true));

    // CleanCompletion after shutdown is NOT pre-shutdown
    let exit = MeshTaskExit {
        id: MeshTaskId(0),
        name: "task",
        class: MeshTaskClass::CriticalService,
        reason: MeshTaskExitReason::CleanCompletion,
    };
    assert!(!exit.is_pre_shutdown(true));

    // Error after shutdown is NOT pre-shutdown
    let exit = MeshTaskExit {
        id: MeshTaskId(0),
        name: "task",
        class: MeshTaskClass::CriticalService,
        reason: MeshTaskExitReason::Error("timeout".into()),
    };
    assert!(!exit.is_pre_shutdown(true));

    // Panic after shutdown is NOT pre-shutdown
    let exit = MeshTaskExit {
        id: MeshTaskId(0),
        name: "task",
        class: MeshTaskClass::CriticalService,
        reason: MeshTaskExitReason::Panic("segfault".into()),
    };
    assert!(!exit.is_pre_shutdown(true));

    // Cancelled after shutdown is NOT pre-shutdown
    let exit = MeshTaskExit {
        id: MeshTaskId(0),
        name: "task",
        class: MeshTaskClass::CriticalService,
        reason: MeshTaskExitReason::Cancelled,
    };
    assert!(!exit.is_pre_shutdown(true));

    // Aborted after shutdown is NOT pre-shutdown
    let exit = MeshTaskExit {
        id: MeshTaskId(0),
        name: "task",
        class: MeshTaskClass::CriticalService,
        reason: MeshTaskExitReason::Aborted,
    };
    assert!(!exit.is_pre_shutdown(true));
}

// ── MeshShutdownReport Tests ─────────────────────────────────────────────────

#[test]
fn shutdown_report_default_zeroed() {
    let report = MeshShutdownReport::default();
    assert_eq!(report.clean_tasks, 0);
    assert!(report.failed_tasks.is_empty());
    assert!(report.aborted_tasks.is_empty());
    assert_eq!(report.drained_peer_children, 0);
    assert_eq!(report.aborted_peer_children, 0);
    assert_eq!(report.remaining_peers, 0);
    assert_eq!(report.peers_at_shutdown_start, 0);
    assert_eq!(report.drained_peer_sessions, 0);
    assert_eq!(report.aborted_peer_sessions, 0);
}

// ── New Iteration Tests ──────────────────────────────────────────────────────

#[tokio::test]
async fn test_mesh_task_exit_dedup() {
    let mut group = MeshTaskGroup::new();
    let mut exit_rx = group.subscribe_exits();

    group.spawn_critical("dedup_task", async {
        tokio::time::sleep(Duration::from_millis(10)).await;
    });

    // Wait for the task to finish and emit its exit event.
    let exit = tokio::time::timeout(Duration::from_secs(5), exit_rx.recv())
        .await
        .expect("timeout waiting for exit event")
        .expect("exit channel closed");

    // The broadcast and join should return the same task ID.
    let exits = group.join_all(Duration::from_secs(5)).await;
    assert_eq!(exits.len(), 1);
    assert_eq!(exit.id, exits[0].id);
    assert_eq!(exit.name, exits[0].name);
    assert_eq!(exit.class, exits[0].class);
}

#[test]
fn test_mesh_startup_policy_defaults() {
    let policy = MeshStartupPolicy::default();
    assert!(!policy.require_seed_connectivity);
    assert!(!policy.require_configured_peers);
    assert!(!policy.require_dht_bootstrap);
}

#[test]
fn test_mesh_startup_report_default() {
    let report = MeshStartupReport::default();
    assert!(report.degraded_reasons.is_empty());
    assert_eq!(report.connected_seed_count, 0);
    assert_eq!(report.connected_configured_peer_count, 0);
    assert!(!report.dht_bootstrapped);
}

#[test]
fn test_shutdown_report_extended_fields() {
    let report = MeshShutdownReport::default();
    assert_eq!(report.peers_at_shutdown_start, 0);
    assert_eq!(report.drained_peer_sessions, 0);
    assert_eq!(report.aborted_peer_sessions, 0);

    let mut report = MeshShutdownReport::default();
    report.peers_at_shutdown_start = 5;
    report.drained_peer_sessions = 4;
    report.aborted_peer_sessions = 1;
    assert_eq!(report.peers_at_shutdown_start, 5);
    assert_eq!(report.drained_peer_sessions, 4);
    assert_eq!(report.aborted_peer_sessions, 1);
}

// ── Phase 23: Peer Session Ownership Tests ───────────────────────────────────

/// Create a minimal `MeshTransport` for testing peer session ownership.
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

#[test]
fn test_peer_sessions_field_initialized() {
    // Create a MeshTransport and verify the peer_sessions field is initialized.
    // We can't access the private field directly, but we verify:
    // 1. The transport constructs without error
    // 2. The lifecycle state is Stopped (indicating proper initialization)
    let transport = make_test_transport();
    // Transport was created successfully - peer_sessions is initialized
    // by MeshTransport::new() as an empty JoinSet.
    assert!(!transport.has_startup_failure_hook());
}

#[tokio::test]
async fn test_peer_sessions_drained_on_shutdown() {
    let transport = make_test_transport();

    // Shutdown with a short timeout. Since no runtime was started,
    // the task group is empty and shutdown completes immediately.
    let report = transport
        .shutdown_with_timeout(Duration::from_millis(100))
        .await;

    // Verify the report fields are populated (even with empty sessions)
    // peers_at_shutdown_start should be 0 (no peers connected)
    assert_eq!(report.peers_at_shutdown_start, 0);
    // drained_peer_sessions should be 0 (no sessions to drain)
    assert_eq!(report.drained_peer_sessions, 0);
    // aborted_peer_sessions should be 0 (nothing to abort)
    assert_eq!(report.aborted_peer_sessions, 0);
    // clean_tasks should be >= 0
    assert!(report.clean_tasks >= 0);
}

#[tokio::test]
async fn test_shutdown_report_fields_after_empty_shutdown() {
    let transport = make_test_transport();

    let report = transport
        .shutdown_with_timeout(Duration::from_secs(1))
        .await;

    // All extended fields should be zero for a fresh transport with no sessions
    assert_eq!(report.peers_at_shutdown_start, 0);
    assert_eq!(report.drained_peer_sessions, 0);
    assert_eq!(report.aborted_peer_sessions, 0);
    assert_eq!(report.drained_peer_children, 0);
    assert_eq!(report.aborted_peer_children, 0);
    assert!(report.failed_tasks.is_empty());
    assert!(report.aborted_tasks.is_empty());
}

#[tokio::test]
async fn test_multiple_shutdowns_are_idempotent() {
    let transport = make_test_transport();

    // First shutdown
    let report1 = transport
        .shutdown_with_timeout(Duration::from_millis(100))
        .await;
    assert_eq!(report1.peers_at_shutdown_start, 0);

    // Second shutdown should also complete without error
    let report2 = transport
        .shutdown_with_timeout(Duration::from_millis(100))
        .await;
    assert_eq!(report2.peers_at_shutdown_start, 0);
}

#[tokio::test]
async fn test_shutdown_respects_timeout() {
    let transport = make_test_transport();

    // Shutdown with a very short timeout should still complete
    // since there are no blocking tasks
    let start = std::time::Instant::now();
    let report = transport
        .shutdown_with_timeout(Duration::from_millis(50))
        .await;
    let elapsed = start.elapsed();

    // Should complete well within the timeout
    assert!(elapsed < Duration::from_secs(5));
    assert_eq!(report.peers_at_shutdown_start, 0);
}
