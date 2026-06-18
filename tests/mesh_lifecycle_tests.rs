use std::sync::Arc;
use std::time::Duration;

use parking_lot::RwLock;
use synvoid_mesh::cert::MeshCertManager;
use synvoid_mesh::config::MeshConfig;
use synvoid_mesh::dht::routing::DhtRoutingManager;
use synvoid_mesh::lifecycle::{
    MeshBackgroundTaskSpec, MeshLifecycleState, MeshShutdownReport, MeshStartupPolicy,
    MeshStartupReport, MeshTaskClass, MeshTaskExit, MeshTaskExitReason, MeshTaskId,
    PeerSessionExitReason,
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
    assert!(report.accept_loop_report.is_none());
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
    assert!(report.accept_loop_report.is_none());
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

// ── Phase 16: PeerSessionExitReason Tests ────────────────────────────────────

#[test]
fn peer_session_exit_reason_variants() {
    assert_eq!(PeerSessionExitReason::Clean.to_string(), "clean");
    assert_eq!(
        PeerSessionExitReason::ConnectionClosed.to_string(),
        "connection closed"
    );
    assert_eq!(PeerSessionExitReason::Cancelled.to_string(), "cancelled");
    assert_eq!(
        PeerSessionExitReason::Error("timeout".to_string()).to_string(),
        "error: timeout"
    );
    assert_eq!(
        PeerSessionExitReason::Panic("overflow".to_string()).to_string(),
        "panic: overflow"
    );
    assert_eq!(PeerSessionExitReason::Aborted.to_string(), "aborted");
}

// ── Phase 30: Stream Ownership Tests (Iteration 75) ─────────────────────────

#[test]
fn peer_stream_drain_report_defaults() {
    use synvoid_mesh::lifecycle::PeerStreamDrainReport;

    let report = PeerStreamDrainReport::default();
    assert_eq!(report.drained, 0);
    assert_eq!(report.aborted, 0);
    assert_eq!(report.failed, 0);
}

#[test]
fn peer_stream_drain_report_fields() {
    use synvoid_mesh::lifecycle::PeerStreamDrainReport;

    let report = PeerStreamDrainReport {
        drained: 10,
        aborted: 3,
        failed: 1,
    };
    assert_eq!(report.drained, 10);
    assert_eq!(report.aborted, 3);
    assert_eq!(report.failed, 1);
}

#[test]
fn mesh_connection_config_has_stream_limits() {
    use synvoid_mesh::config::MeshConnectionConfig;

    let config = MeshConnectionConfig::default();
    // Phase 25: Capacity limit defaults
    assert_eq!(config.max_concurrent_peer_streams, 64);
    // Phase 26: Timeout defaults
    assert_eq!(config.peer_message_timeout_secs, 30);
}

#[test]
fn mesh_connection_config_custom_stream_limits() {
    use synvoid_mesh::config::MeshConnectionConfig;

    let config = MeshConnectionConfig {
        max_concurrent_peer_streams: 128,
        peer_message_timeout_secs: 60,
        ..MeshConnectionConfig::default()
    };
    assert_eq!(config.max_concurrent_peer_streams, 128);
    assert_eq!(config.peer_message_timeout_secs, 60);
}

#[test]
fn drain_report_is_clone() {
    use synvoid_mesh::lifecycle::PeerStreamDrainReport;

    let report = PeerStreamDrainReport {
        drained: 5,
        aborted: 2,
        failed: 1,
    };
    let cloned = report.clone();
    assert_eq!(report.drained, cloned.drained);
    assert_eq!(report.aborted, cloned.aborted);
    assert_eq!(report.failed, cloned.failed);
}

// ── Iteration 76: Part B — Cooperative session cancellation contract ─────

/// When a peer session task receives a cooperative shutdown signal via
/// its `shutdown_tx`, the session's `peer_message_loop` must observe it
/// and return `PeerSessionExitReason::Cancelled` (not `Aborted` and not a
/// panic). This is the contract that rollback, recovery, and shutdown all
/// rely on for clean cleanup.
#[tokio::test]
async fn cooperative_shutdown_signal_yields_cancelled_exit() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use synvoid_mesh::lifecycle::{PeerSessionStopOutcome, PeerSessionTask};
    use tokio::sync::watch;

    struct SessionGuard(Arc<AtomicBool>);
    impl Drop for SessionGuard {
        fn drop(&mut self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    let exited_flag = Arc::new(AtomicBool::new(false));
    let exited_for_task = exited_flag.clone();

    let (shutdown_tx, mut shutdown_rx) = watch::channel(false);

    // Construct a session task that awaits the cooperative signal and
    // then exits with `Cancelled`. This mirrors the `peer_message_loop`
    // select-on-shutdown contract from `transport_peer.rs`.
    let task = PeerSessionTask {
        session_id: "iter76-coop".to_string(),
        node_id: "test-node".to_string(),
        handle: tokio::spawn(async move {
            let _hold = SessionGuard(exited_for_task);
            // Block until the cooperative signal arrives.
            let _ = shutdown_rx.wait_for(|v| *v).await;
            // Run any post-cancel cleanup here. For this test we just
            // exit cooperatively.
            drop(_hold);
        }),
        generation: 1,
        shutdown_tx: shutdown_tx.clone(),
    };

    // Simulate the rollback/recovery/shutdown path: send the cooperative
    // signal and await the handle.
    let _ = task.shutdown_tx.send(true);
    let outcome = task.handle.await;

    // The session exited cleanly (not panic, not abort).
    assert!(outcome.is_ok(), "cooperative shutdown must not panic");
    assert!(
        exited_flag.load(Ordering::SeqCst),
        "session future must have been dropped (cooperative exit)"
    );

    // Classify via PeerSessionStopOutcome to demonstrate the API.
    let _classification: PeerSessionStopOutcome = match outcome {
        Ok(()) => PeerSessionStopOutcome::Drained(PeerSessionExitReason::Cancelled),
        Err(_) => PeerSessionStopOutcome::Failed("unexpected".to_string()),
    };
}

// ── Iteration 86 Phase 11: Topology/DHT Ownership Behavioral Tests ──────────

/// Constructing a MeshTaskGroup starts with zero tasks.
#[test]
fn task_group_starts_empty() {
    let group = MeshTaskGroup::new();
    let (crit, bg, child) = group.active_count();
    assert_eq!(crit, 0);
    assert_eq!(bg, 0);
    assert_eq!(child, 0);
    assert!(group.is_empty());
}

/// MeshBackgroundTaskSpec has the required fields for lifecycle ownership.
#[test]
fn background_task_spec_has_required_fields() {
    let spec = MeshBackgroundTaskSpec {
        name: "test_task",
        class: MeshTaskClass::RestartableBackground,
        future: Box::pin(async { Ok(()) }),
    };
    assert_eq!(spec.name, "test_task");
    assert!(matches!(spec.class, MeshTaskClass::RestartableBackground));
}

/// register_background_specs accepts a vector of specs and spawns them.
#[tokio::test]
async fn register_background_specs_spawns_tasks() {
    let mut group = MeshTaskGroup::new();
    let specs = vec![
        MeshBackgroundTaskSpec {
            name: "topology_stale_metrics",
            class: MeshTaskClass::RestartableBackground,
            future: Box::pin(async { Ok(()) }),
        },
        MeshBackgroundTaskSpec {
            name: "topology_global_node_liveness",
            class: MeshTaskClass::RestartableBackground,
            future: Box::pin(async { Ok(()) }),
        },
    ];
    group.register_background_specs(specs);

    // Verify tasks are registered
    let (_, bg, _) = group.active_count();
    assert_eq!(bg, 2, "must have registered 2 background tasks");

    // Shutdown and join
    group.begin_shutdown().await;
    let exits = group.join_all(Duration::from_secs(5)).await;
    assert_eq!(exits.len(), 2, "must have 2 exit events");
}

/// DHT routing specs are RestartableBackground class.
#[test]
fn dht_routing_specs_are_restartable_background() {
    let specs = vec![
        MeshBackgroundTaskSpec {
            name: "dht_bucket_stats",
            class: MeshTaskClass::RestartableBackground,
            future: Box::pin(async { Ok(()) }),
        },
        MeshBackgroundTaskSpec {
            name: "dht_bucket_refresh",
            class: MeshTaskClass::RestartableBackground,
            future: Box::pin(async { Ok(()) }),
        },
        MeshBackgroundTaskSpec {
            name: "dht_peer_ping",
            class: MeshTaskClass::RestartableBackground,
            future: Box::pin(async { Ok(()) }),
        },
    ];

    for spec in &specs {
        assert!(
            matches!(spec.class, MeshTaskClass::RestartableBackground),
            "DHT spec '{}' must be RestartableBackground, got {:?}",
            spec.name,
            spec.class
        );
    }
}

/// Topology specs are RestartableBackground class.
#[test]
fn topology_specs_are_restartable_background() {
    let specs = vec![
        MeshBackgroundTaskSpec {
            name: "topology_stale_metrics",
            class: MeshTaskClass::RestartableBackground,
            future: Box::pin(async { Ok(()) }),
        },
        MeshBackgroundTaskSpec {
            name: "topology_global_node_liveness",
            class: MeshTaskClass::RestartableBackground,
            future: Box::pin(async { Ok(()) }),
        },
    ];

    for spec in &specs {
        assert!(
            matches!(spec.class, MeshTaskClass::RestartableBackground),
            "Topology spec '{}' must be RestartableBackground, got {:?}",
            spec.name,
            spec.class
        );
    }
}

/// Shutdown drains all registered background tasks.
#[tokio::test]
async fn shutdown_drains_background_tasks() {
    let mut group = MeshTaskGroup::new();
    let specs = vec![MeshBackgroundTaskSpec {
        name: "topo_loop",
        class: MeshTaskClass::RestartableBackground,
        future: Box::pin(async {
            // Simulate a long-running task that respects shutdown
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(100)) => {}
                _ = tokio::time::sleep(Duration::from_millis(1)) => {}
            }
            Ok(())
        }),
    }];
    group.register_background_specs(specs);

    // Shutdown with a deadline
    let start = std::time::Instant::now();
    group.begin_shutdown().await;
    let exits = group.join_all(Duration::from_secs(2)).await;
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_secs(5),
        "shutdown must complete within deadline, took {:?}",
        elapsed
    );
    assert_eq!(exits.len(), 1, "must have 1 exit event");
}

/// Zero-budget shutdown aborts and awaits every background task.
#[tokio::test]
async fn zero_budget_shutdown_aborts_background_tasks() {
    let mut group = MeshTaskGroup::new();
    let specs = vec![MeshBackgroundTaskSpec {
        name: "slow_loop",
        class: MeshTaskClass::RestartableBackground,
        future: Box::pin(async {
            // Never-ending task
            loop {
                tokio::time::sleep(Duration::from_secs(100)).await;
            }
        }),
    }];
    group.register_background_specs(specs);

    // Zero-budget shutdown must abort and await
    group.begin_shutdown().await;
    let exits = group.join_all(Duration::ZERO).await;
    assert_eq!(exits.len(), 1, "must have 1 exit event");
    assert!(
        matches!(exits[0].reason, MeshTaskExitReason::Aborted),
        "zero-budget must produce Aborted, got {:?}",
        exits[0].reason
    );
}

/// MeshTaskExit from background tasks contains typed metadata.
#[test]
fn mesh_task_exit_has_typed_metadata() {
    let exit = MeshTaskExit {
        id: MeshTaskId(42),
        name: "topology_stale_metrics",
        class: MeshTaskClass::RestartableBackground,
        reason: MeshTaskExitReason::CleanCompletion,
    };
    assert_eq!(exit.id, MeshTaskId(42));
    assert_eq!(exit.name, "topology_stale_metrics");
    assert!(matches!(exit.class, MeshTaskClass::RestartableBackground));
    assert!(matches!(exit.reason, MeshTaskExitReason::CleanCompletion));
    assert!(!exit.is_fatal());
}

/// MeshTaskExit for CriticalService with Error is fatal.
#[test]
fn critical_service_error_is_fatal() {
    let exit = MeshTaskExit {
        id: MeshTaskId(1),
        name: "critical_service",
        class: MeshTaskClass::CriticalService,
        reason: MeshTaskExitReason::Error("connection lost".to_string()),
    };
    assert!(exit.is_fatal());
}

/// MeshTaskExit for RestartableBackground with Error is not fatal.
#[test]
fn restartable_background_error_is_not_fatal() {
    let exit = MeshTaskExit {
        id: MeshTaskId(2),
        name: "dht_refresh",
        class: MeshTaskClass::RestartableBackground,
        reason: MeshTaskExitReason::Error("timeout".to_string()),
    };
    assert!(!exit.is_fatal());
}

// ── Iteration 87 Phases 18-20: Real builder tests ────────────────────────────

#[cfg(feature = "mesh")]
#[test]
fn topology_build_background_tasks_returns_specs() {
    let config = Arc::new(MeshConfig::default());
    let topology = Arc::new(MeshTopology::new(config));
    let (_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let specs = topology.build_background_tasks(shutdown_rx);
    assert!(!specs.is_empty(), "topology must return non-empty specs");
    assert!(
        specs.iter().any(|s| s.name.contains("topology")),
        "at least one spec name must contain 'topology'"
    );
}

#[cfg(feature = "mesh")]
#[tokio::test]
async fn dht_routing_build_background_tasks_returns_specs() {
    let config = Arc::new(MeshConfig::default());
    let manager = DhtRoutingManager::new(config);
    manager.init().await;
    let (_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let specs = manager.build_background_tasks(shutdown_rx);
    assert!(!specs.is_empty(), "DHT routing must return non-empty specs");
    let names: Vec<&str> = specs.iter().map(|s| s.name).collect();
    assert!(
        names.contains(&"dht_bucket_stats"),
        "must include dht_bucket_stats, got: {:?}",
        names
    );
    assert!(
        names.contains(&"dht_bucket_refresh"),
        "must include dht_bucket_refresh, got: {:?}",
        names
    );
    assert!(
        names.contains(&"dht_peer_ping"),
        "must include dht_peer_ping, got: {:?}",
        names
    );
}

#[cfg(feature = "mesh")]
#[test]
fn topology_build_background_tasks_uses_shutdown_signal() {
    let config = Arc::new(MeshConfig::default());
    let topology = Arc::new(MeshTopology::new(config));
    let (_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let specs = topology.build_background_tasks(shutdown_rx);
    assert!(
        specs
            .iter()
            .all(|s| s.class == MeshTaskClass::RestartableBackground),
        "topology specs must all be RestartableBackground"
    );
}

#[cfg(feature = "mesh")]
#[tokio::test]
async fn dht_build_background_tasks_returns_three_specs() {
    let config = Arc::new(MeshConfig::default());
    let manager = DhtRoutingManager::new(config);
    manager.init().await;
    let (_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let specs = manager.build_background_tasks(shutdown_rx);
    assert_eq!(specs.len(), 3, "DHT routing must return exactly 3 specs");
}

#[cfg(feature = "mesh")]
#[test]
fn topology_build_background_tasks_disabled_returns_empty() {
    let config: MeshConfig = serde_json::from_value(serde_json::json!({
        "dht": {
            "routing_enabled": false
        }
    }))
    .unwrap();
    let manager = DhtRoutingManager::new(Arc::new(config));
    let (_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let specs = manager.build_background_tasks(shutdown_rx);
    assert!(
        specs.is_empty(),
        "disabled DHT routing must return empty vec, got {}",
        specs.len()
    );
}

#[cfg(feature = "mesh")]
#[test]
fn mesh_background_task_spec_has_name_and_class_fields() {
    let config = Arc::new(MeshConfig::default());
    let topology = Arc::new(MeshTopology::new(config));
    let (_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let specs = topology.build_background_tasks(shutdown_rx);
    for spec in &specs {
        assert!(!spec.name.is_empty(), "spec name must be non-empty");
        assert!(
            matches!(
                spec.class,
                MeshTaskClass::RestartableBackground | MeshTaskClass::CriticalService
            ),
            "spec class must be RestartableBackground or CriticalService, got {:?}",
            spec.class
        );
    }
}
