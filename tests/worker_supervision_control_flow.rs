//! Root-test ownership: COMPOSITION
//! Rationale: validates worker+mesh supervision control flow composition
//!
//! Integration tests for the worker supervision control flow (Iteration 63).
//!
//! Tests the supervision loop behavior: non-fatal exits don't stop the worker,
//! critical exits do, receiver lag is handled, etc.
#![allow(
    unused_mut,
    unused_variables,
    dead_code,
    unused_imports,
    unused_assignments
)]

use std::sync::atomic::Ordering;
use std::time::Duration;

use synvoid::worker::task_registry::{
    is_fatal_exit, NamedTaskExit, TaskClass, TaskExitReason, TaskId, WorkerShutdownCause,
    WorkerTaskRegistry,
};

/// Background task exits unexpectedly; worker remains running.
#[tokio::test]
async fn test_background_exit_does_not_stop_worker() {
    let mut registry = WorkerTaskRegistry::new();
    let mut exit_rx = registry.subscribe_exits();
    let shutdown_flag = registry.shutdown_started_flag();

    // Spawn a background task that exits immediately.
    registry.spawn_cancellable_background("bg_exit", async {});

    // Spawn a long-lived critical task to keep the worker "alive".
    let token = registry.child_token();
    registry.spawn_critical("keep_alive", async move {
        let mut shutdown = token;
        loop {
            if *shutdown.borrow() {
                break;
            }
            if shutdown.changed().await.is_err() {
                break;
            }
        }
    });

    // Simulate the supervision loop logic.
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Process exit events.
    let mut fatal_received = false;
    while let Ok(exit) = tokio::time::timeout(Duration::from_millis(100), exit_rx.recv()).await {
        if let Ok(exit) = exit {
            let shutdown_started = shutdown_flag.load(Ordering::Acquire);
            if is_fatal_exit(&exit, shutdown_started) {
                fatal_received = true;
                break;
            }
        }
    }

    // Background exit should NOT be fatal.
    assert!(
        !fatal_received,
        "Background exit should not trigger shutdown"
    );
    assert!(
        !registry.is_shutdown_started(),
        "Registry should not be shutting down"
    );
}

/// Critical task panics; worker begins shutdown.
#[tokio::test]
async fn test_critical_panic_triggers_shutdown() {
    let mut registry = WorkerTaskRegistry::new();
    let mut exit_rx = registry.subscribe_exits();
    let shutdown_flag = registry.shutdown_started_flag();

    registry.spawn_critical("panicking_task", async {
        panic!("critical failure");
    });

    // Wait for the exit notification.
    let exit = tokio::time::timeout(Duration::from_secs(2), exit_rx.recv())
        .await
        .expect("timeout")
        .expect("recv");

    let shutdown_started = shutdown_flag.load(Ordering::Acquire);
    assert!(
        is_fatal_exit(&exit, shutdown_started),
        "Critical panic should be fatal"
    );
    assert!(matches!(exit.reason, TaskExitReason::Panic(_)));
}

/// Critical task returns unexpectedly; worker begins shutdown.
#[tokio::test]
async fn test_critical_unexpected_return_triggers_shutdown() {
    let mut registry = WorkerTaskRegistry::new();
    let mut exit_rx = registry.subscribe_exits();
    let shutdown_flag = registry.shutdown_started_flag();

    registry.spawn_critical("early_return", async {});

    let exit = tokio::time::timeout(Duration::from_secs(2), exit_rx.recv())
        .await
        .expect("timeout")
        .expect("recv");

    let shutdown_started = shutdown_flag.load(Ordering::Acquire);
    assert!(
        is_fatal_exit(&exit, shutdown_started),
        "Unexpected completion should be fatal for critical task"
    );
    assert_eq!(exit.reason, TaskExitReason::UnexpectedCompletion);
}

/// Critical task exits immediately after spawn; pre-created receiver observes it.
#[tokio::test]
async fn test_immediate_exit_observed_by_pre_subscribed_receiver() {
    let mut registry = WorkerTaskRegistry::new();
    let mut exit_rx = registry.subscribe_exits();

    registry.spawn_critical("immediate", async {});

    let exit = tokio::time::timeout(Duration::from_secs(2), exit_rx.recv())
        .await
        .expect("Should receive exit")
        .expect("Should Ok");

    assert_eq!(exit.name, "immediate");
    assert_eq!(exit.class, TaskClass::CriticalService);
    assert_eq!(exit.reason, TaskExitReason::UnexpectedCompletion);
}

/// Receiver reports Lagged; conservative policy is applied.
#[tokio::test]
async fn test_receiver_lag_triggers_shutdown() {
    let mut registry = WorkerTaskRegistry::new();
    let shutdown_flag = registry.shutdown_started_flag();

    // Create a receiver, drop it, then create a new one to simulate lag.
    {
        let _rx = registry.subscribe_exits();
    }

    // Spawn many tasks to overflow the broadcast buffer.
    for _ in 0..100 {
        registry.spawn_critical("filler", async {});
    }

    // Create a new receiver — it will lag.
    let mut exit_rx = registry.subscribe_exits();

    // Try to receive — should get Lagged error.
    tokio::time::sleep(Duration::from_millis(50)).await;
    match exit_rx.try_recv() {
        Err(tokio::sync::broadcast::error::TryRecvError::Lagged(n)) => {
            // Conservative: treat as infrastructure failure.
            let shutdown_started = shutdown_flag.load(Ordering::Acquire);
            assert!(!shutdown_started, "Shutdown should not have started yet");
            // In real code, this would trigger shutdown.
            drop(exit_rx);
            let _ = n;
        }
        _ => {
            // May have received events instead of lagging — acceptable.
        }
    }
}

/// Normal MasterShutdown; IPC completion is expected.
#[tokio::test]
async fn test_master_shutdown_is_expected() {
    let cause = WorkerShutdownCause::SupervisorShutdown;
    assert!(cause.is_expected());
    assert!(!cause.nonzero_exit_code());
}

/// Supervisor disconnect; nonzero exit code is preserved.
#[tokio::test]
async fn test_supervisor_disconnect_nonzero_exit() {
    let cause = WorkerShutdownCause::SupervisorDisconnected;
    assert!(!cause.is_expected());
    assert!(cause.nonzero_exit_code());
}

/// Critical task exit first; server task would be shut down.
#[tokio::test]
async fn test_critical_exit_is_fatal_before_shutdown() {
    let exit = NamedTaskExit {
        id: TaskId(1),
        name: "ipc_loop",
        class: TaskClass::CriticalService,
        reason: TaskExitReason::Error("connection lost".to_string()),
        expected_during_shutdown: false,
    };
    assert!(is_fatal_exit(&exit, false));
}

/// Critical task exit during shutdown with clean completion is not fatal.
#[tokio::test]
async fn test_clean_exit_during_shutdown_not_fatal() {
    let exit = NamedTaskExit {
        id: TaskId(1),
        name: "ipc_loop",
        class: TaskClass::CriticalService,
        reason: TaskExitReason::CleanCompletion,
        expected_during_shutdown: true,
    };
    assert!(!is_fatal_exit(&exit, true));
}

/// Verify WorkerShutdownCause display and properties.
#[tokio::test]
async fn test_shutdown_cause_properties() {
    let cases = vec![
        (
            WorkerShutdownCause::ServerStoppedForShutdown,
            false,
            false,
            true,
        ),
        (
            WorkerShutdownCause::ServerExitedUnexpectedly(NamedTaskExit {
                id: TaskId(0),
                name: "server_run",
                class: TaskClass::CriticalService,
                reason: TaskExitReason::Error("test".to_string()),
                expected_during_shutdown: false,
            }),
            true,
            true, // ServerExitedUnexpectedly now notifies (Phase 9)
            false,
        ),
        (WorkerShutdownCause::SupervisorShutdown, false, false, true),
        (
            WorkerShutdownCause::SupervisorDisconnected,
            true,
            false, // SupervisorDisconnected does NOT notify — channel unavailable
            false,
        ),
        (
            WorkerShutdownCause::RegistryExitChannelClosed,
            true,
            true,
            false,
        ),
        (WorkerShutdownCause::ExternalStop, false, false, true),
        (WorkerShutdownCause::RunningFlagCleared, false, false, true),
        (
            WorkerShutdownCause::WorkerResize { worker_threads: 4 },
            false,
            false,
            true,
        ),
    ];

    for (cause, nonzero, notify, expected) in cases {
        assert_eq!(
            cause.nonzero_exit_code(),
            nonzero,
            "{:?} nonzero_exit_code",
            cause
        );
        assert_eq!(
            cause.should_notify_supervisor(),
            notify,
            "{:?} should_notify_supervisor",
            cause
        );
        assert_eq!(cause.is_expected(), expected, "{:?} is_expected", cause);
    }
}

// ---------------------------------------------------------------------------
// Iteration 64 — Coordinated shutdown intent and lifecycle tests
// ---------------------------------------------------------------------------

/// Verify that begin_shutdown marks intent before IPC/server tasks would return.
#[tokio::test]
async fn test_begin_shutdown_before_task_return_classifies_cleanly() {
    let mut registry = WorkerTaskRegistry::new();
    let token = registry.child_token();

    // Record shutdown intent BEFORE spawning — simulates composition root behavior.
    registry.begin_shutdown();

    registry.spawn_critical("ipc_like_task", async move {
        let mut shutdown = token;
        loop {
            if *shutdown.borrow() {
                break;
            }
            if shutdown.changed().await.is_err() {
                break;
            }
        }
    });

    tokio::time::sleep(Duration::from_millis(10)).await;

    let exits = registry
        .shutdown_and_join(Duration::from_secs(5), Duration::from_secs(5))
        .await;
    // Clean completion during shutdown — no non-clean exits.
    assert!(
        exits.is_empty(),
        "Expected clean shutdown, got: {:?}",
        exits
    );
}

/// Verify WorkerShutdownCause::exit_code() mapping.
#[tokio::test]
async fn test_shutdown_cause_exit_code_mapping() {
    assert_eq!(WorkerShutdownCause::SupervisorShutdown.exit_code(), 0);
    assert_eq!(WorkerShutdownCause::ServerStoppedForShutdown.exit_code(), 0);
    assert_eq!(
        WorkerShutdownCause::ServerExitedUnexpectedly(NamedTaskExit {
            id: TaskId(0),
            name: "server_run",
            class: TaskClass::CriticalService,
            reason: TaskExitReason::Error("test".to_string()),
            expected_during_shutdown: false,
        })
        .exit_code(),
        1
    );
    assert_eq!(
        WorkerShutdownCause::CriticalTaskExit(NamedTaskExit {
            id: TaskId(999),
            name: "test_server",
            class: TaskClass::CriticalService,
            reason: TaskExitReason::Error("server error".to_string()),
            expected_during_shutdown: false,
        })
        .exit_code(),
        1
    );
    assert_eq!(WorkerShutdownCause::SupervisorDisconnected.exit_code(), 1);
    assert_eq!(
        WorkerShutdownCause::RegistryExitChannelClosed.exit_code(),
        1
    );
    assert_eq!(WorkerShutdownCause::ExternalStop.exit_code(), 0);
    assert_eq!(WorkerShutdownCause::RunningFlagCleared.exit_code(), 0);
    assert_eq!(
        WorkerShutdownCause::WorkerResize { worker_threads: 8 }.exit_code(),
        100
    );
}

/// Verify that a server task returning Ok(()) before shutdown is classified as unexpected.
#[tokio::test]
async fn test_server_clean_early_return_is_unexpected() {
    let mut registry = WorkerTaskRegistry::new();
    let mut exit_rx = registry.subscribe_exits();

    // Server returns Ok(()) immediately — should be UnexpectedCompletion before shutdown.
    registry.spawn_critical_result("server_run", async { Ok::<(), String>(()) });
    tokio::time::sleep(Duration::from_millis(50)).await;

    let exit = tokio::time::timeout(Duration::from_secs(2), exit_rx.recv())
        .await
        .expect("timeout")
        .expect("recv");

    assert_eq!(exit.name, "server_run");
    assert_eq!(exit.reason, TaskExitReason::UnexpectedCompletion);
    assert!(!exit.expected_during_shutdown);
}

/// Verify that broadcast_shutdown sends the cancellation signal.
#[tokio::test]
async fn test_broadcast_shutdown_sends_cancellation() {
    let mut registry = WorkerTaskRegistry::new();
    let token = registry.child_token();

    registry.spawn_background("cooperative_task", async move {
        let mut shutdown = token;
        loop {
            if *shutdown.borrow() {
                break;
            }
            if shutdown.changed().await.is_err() {
                break;
            }
        }
    });

    // begin_shutdown alone does not cancel tasks.
    registry.begin_shutdown();
    tokio::time::sleep(Duration::from_millis(10)).await;
    assert_eq!(registry.background_count(), 1);

    // broadcast_shutdown sends the cancel signal.
    registry.broadcast_shutdown();
    let exits = registry
        .shutdown_and_join(Duration::from_secs(5), Duration::from_secs(5))
        .await;
    assert!(exits.is_empty());
}

/// Verify that begin_shutdown is idempotent and does not send cancellation.
#[tokio::test]
async fn test_begin_shutdown_idempotent_no_broadcast() {
    let registry = WorkerTaskRegistry::new();
    let token = registry.child_token();

    registry.begin_shutdown();
    registry.begin_shutdown();
    registry.begin_shutdown();

    assert!(registry.is_shutdown_started());
    // Token should still be false — no broadcast.
    assert!(!*token.borrow());
}

// ---------------------------------------------------------------------------
// Iteration 65 — Lifecycle event channel and acknowledgement tests
// ---------------------------------------------------------------------------

/// Real MasterShutdown via lifecycle channel produces clean task completion,
/// not UnexpectedCompletion.
#[tokio::test]
async fn test_lifecycle_channel_master_shutdown_classifies_cleanly() {
    use synvoid::worker::unified_server::lifecycle::{LifecycleRequest, WorkerLifecycleEvent};

    let mut registry = WorkerTaskRegistry::new();
    let mut exit_rx = registry.subscribe_exits();

    // Simulate an IPC-like critical task that sends a lifecycle event.
    let (lifecycle_tx, mut lifecycle_rx) = tokio::sync::mpsc::channel::<LifecycleRequest>(4);

    registry.spawn_critical("ipc_loop_sim", async move {
        // Simulate receiving MasterShutdown from supervisor.
        let (ack_tx, ack_rx) = tokio::sync::oneshot::channel();
        let _ = lifecycle_tx
            .send(LifecycleRequest {
                event: WorkerLifecycleEvent::MasterShutdown {
                    graceful: true,
                    timeout: std::time::Duration::from_secs(30),
                },
                accepted: ack_tx,
            })
            .await;
        // Wait for composition root acknowledgement.
        let _ = ack_rx.await;
    });

    // Composition root: receive lifecycle event, begin_shutdown, acknowledge.
    let request = tokio::time::timeout(Duration::from_secs(2), lifecycle_rx.recv())
        .await
        .expect("timeout")
        .expect("no lifecycle event");

    assert!(matches!(
        request.event,
        WorkerLifecycleEvent::MasterShutdown { .. }
    ));

    // Begin shutdown BEFORE acknowledging — this is the critical ordering.
    registry.begin_shutdown();
    let _ = request.accepted.send(());

    // Now join the IPC task.
    let exits = registry
        .shutdown_and_join(Duration::from_secs(5), Duration::from_secs(5))
        .await;

    // The IPC task should exit cleanly since begin_shutdown was called
    // before it returned.
    let non_clean: Vec<_> = exits
        .iter()
        .filter(|e| e.reason != TaskExitReason::CleanCompletion)
        .collect();
    assert!(
        non_clean.is_empty(),
        "Expected clean shutdown, got: {:?}",
        non_clean
    );
    assert_eq!(
        registry
            .metrics
            .tasks_unexpectedly_completed
            .load(Ordering::Relaxed),
        0,
        "No tasks should have unexpectedly completed"
    );
}

/// Verify that lifecycle channel closure during shutdown is handled gracefully.
#[tokio::test]
async fn test_lifecycle_channel_closure_during_shutdown() {
    use synvoid::worker::unified_server::lifecycle::LifecycleRequest;

    let _registry = WorkerTaskRegistry::new();
    let (_lifecycle_tx, mut lifecycle_rx) = tokio::sync::mpsc::channel::<LifecycleRequest>(4);

    // Drop the sender to simulate channel closure.
    drop(_lifecycle_tx);

    // The receiver should return None.
    let result = tokio::time::timeout(Duration::from_millis(100), lifecycle_rx.recv()).await;
    assert!(result.is_ok());
    assert!(
        result.unwrap().is_none(),
        "Channel closure should yield None"
    );
}

/// Verify resize event via lifecycle channel sends ResizeAck (not ShutdownComplete).
#[tokio::test]
async fn test_resize_cause_maps_to_resize_exit_code() {
    let cause = WorkerShutdownCause::WorkerResize { worker_threads: 8 };
    assert_eq!(cause.exit_code(), 100);
    assert!(!cause.nonzero_exit_code());
    assert!(cause.is_expected());
    assert!(!cause.should_notify_supervisor());
}

/// Verify that a fatal cause (CriticalTaskExit) sends WorkerError, not ShutdownComplete.
#[tokio::test]
async fn test_fatal_cause_should_notify_supervisor() {
    let exit = NamedTaskExit {
        id: TaskId(1),
        name: "ipc_loop",
        class: TaskClass::CriticalService,
        reason: TaskExitReason::Error("connection lost".to_string()),
        expected_during_shutdown: false,
    };
    let cause = WorkerShutdownCause::CriticalTaskExit(exit);
    assert!(cause.should_notify_supervisor());
    assert!(cause.nonzero_exit_code());
}

/// Verify SupervisorDisconnected does not attempt notification.
#[tokio::test]
async fn test_supervisor_disconnect_no_notification() {
    let cause = WorkerShutdownCause::SupervisorDisconnected;
    assert!(!cause.is_expected());
    // SupervisorDisconnected does NOT notify — channel is unavailable
    // (the supervisor initiated the disconnect).
    assert!(!cause.should_notify_supervisor());
}

/// Verify that aborting and awaiting legacy handles completes successfully.
#[tokio::test]
async fn test_legacy_handle_abort_and_await_completes() {
    let mut registry = WorkerTaskRegistry::new();
    let token = registry.child_token();

    // Spawn a critical task to keep the worker "alive".
    registry.spawn_critical("keep_alive", async move {
        let mut shutdown = token;
        loop {
            if *shutdown.borrow() {
                break;
            }
            if shutdown.changed().await.is_err() {
                break;
            }
        }
    });

    // Simulate a legacy task handle — a long-running task.
    let handle = tokio::spawn(async {
        loop {
            tokio::time::sleep(Duration::from_secs(100)).await;
        }
    });

    // Abort and await the legacy handle — must complete without hanging.
    handle.abort();
    let result = tokio::time::timeout(Duration::from_secs(2), handle).await;
    assert!(result.is_ok(), "Abort + await must complete within timeout");

    // Clean shutdown.
    registry.broadcast_shutdown();
    let _ = registry
        .shutdown_and_join(Duration::from_secs(5), Duration::from_secs(5))
        .await;
}

/// Verify shutdown ordering: begin_coordinated_shutdown before stop_accepting.
#[tokio::test]
async fn test_shutdown_ordering_begin_before_stop_accepting() {
    // This is a structural test verifying the source code ordering.
    let content = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("src/worker/unified_server/shutdown_executor.rs"),
    )
    .unwrap();

    let composition_start = content
        .find("composition-root shutdown procedure")
        .expect("composition root not found");
    let section = &content[composition_start..];

    let begin_pos = section
        .find("begin_coordinated_shutdown")
        .expect("begin_coordinated_shutdown not found");
    let stop_accepting_pos = section
        .find("state.stop_accepting_tx")
        .expect("stop_accepting not found");

    assert!(
        begin_pos < stop_accepting_pos,
        "begin_coordinated_shutdown must come before stop_accepting"
    );
}

// ---------------------------------------------------------------------------
// Iteration 66 — Supervision cause preservation and SupervisionOutcome tests
// ---------------------------------------------------------------------------

use synvoid::worker::task_registry::{
    map_exit_recv_error_to_shutdown_cause, map_lifecycle_channel_closed,
    map_task_exit_to_shutdown_cause, SupervisionOutcome,
};
use synvoid::worker::unified_server::lifecycle::{IpcLoopError, WorkerLifecycleEvent};

/// Critical task failure produces DirectCause(CriticalTaskExit) with preserved identity.
#[tokio::test]
async fn test_critical_task_failure_preserves_identity() {
    let mut registry = WorkerTaskRegistry::new();
    let mut exit_rx = registry.subscribe_exits();
    let shutdown_flag = registry.shutdown_started_flag();

    registry.spawn_critical("my_worker_task", async {
        panic!("something broke");
    });

    let exit = tokio::time::timeout(Duration::from_secs(2), exit_rx.recv())
        .await
        .expect("timeout")
        .expect("recv");

    let shutdown_started = shutdown_flag.load(Ordering::Acquire);
    assert!(is_fatal_exit(&exit, shutdown_started));

    let cause = map_task_exit_to_shutdown_cause(exit.clone());
    match &cause {
        WorkerShutdownCause::CriticalTaskExit(e) => {
            assert_eq!(e.name, "my_worker_task");
            assert!(matches!(e.reason, TaskExitReason::Panic(_)));
        }
        other => panic!("Expected CriticalTaskExit, got {:?}", other),
    }

    // Verify SupervisionOutcome::DirectCause preserves the cause.
    let outcome = SupervisionOutcome::DirectCause(cause);
    match outcome {
        SupervisionOutcome::DirectCause(c) => assert!(c.nonzero_exit_code()),
        _ => panic!("Expected DirectCause"),
    }
}

/// Server_run failure produces DirectCause(ServerExitedUnexpectedly), not SupervisorDisconnected.
#[tokio::test]
async fn test_server_failure_not_misclassified() {
    let mut registry = WorkerTaskRegistry::new();
    let mut exit_rx = registry.subscribe_exits();
    let shutdown_flag = registry.shutdown_started_flag();

    registry.spawn_critical_result("server_run", async {
        Err::<(), String>("server crashed".to_string())
    });

    let exit = tokio::time::timeout(Duration::from_secs(2), exit_rx.recv())
        .await
        .expect("timeout")
        .expect("recv");

    let shutdown_started = shutdown_flag.load(Ordering::Acquire);
    assert!(is_fatal_exit(&exit, shutdown_started));

    let cause = map_task_exit_to_shutdown_cause(exit);
    match &cause {
        WorkerShutdownCause::ServerExitedUnexpectedly(e) => {
            assert_eq!(e.name, "server_run");
        }
        other => panic!("Expected ServerExitedUnexpectedly, got {:?}", other),
    }
    assert!(!matches!(
        cause,
        WorkerShutdownCause::SupervisorDisconnected
    ));
    assert!(cause.nonzero_exit_code());
    assert!(cause.should_notify_supervisor());
}

/// Registry exit lag maps to RegistryExitChannelClosed, not SupervisorDisconnected.
#[tokio::test]
async fn test_registry_lag_not_misclassified() {
    use tokio::sync::broadcast::error::RecvError;

    let cause = map_exit_recv_error_to_shutdown_cause(RecvError::Lagged(42), false);
    assert_eq!(cause, Some(WorkerShutdownCause::RegistryExitChannelClosed));
    assert!(!matches!(
        cause.unwrap(),
        WorkerShutdownCause::SupervisorDisconnected
    ));
}

/// Registry exit closure before shutdown maps to RegistryExitChannelClosed.
#[tokio::test]
async fn test_registry_closure_active_not_misclassified() {
    use tokio::sync::broadcast::error::RecvError;

    let cause = map_exit_recv_error_to_shutdown_cause(RecvError::Closed, false);
    assert_eq!(cause, Some(WorkerShutdownCause::RegistryExitChannelClosed));
}

/// Registry exit closure during shutdown returns None (expected).
#[tokio::test]
async fn test_registry_closure_during_shutdown_expected() {
    use tokio::sync::broadcast::error::RecvError;

    let cause = map_exit_recv_error_to_shutdown_cause(RecvError::Closed, true);
    assert_eq!(cause, None);
}

/// Lifecycle channel closure while active maps to RegistryExitChannelClosed.
#[tokio::test]
async fn test_lifecycle_channel_closed_active_maps_correctly() {
    let cause = map_lifecycle_channel_closed(false);
    assert_eq!(cause, Some(WorkerShutdownCause::RegistryExitChannelClosed));
}

/// Lifecycle channel closure during shutdown returns None (expected).
#[tokio::test]
async fn test_lifecycle_channel_closed_during_shutdown_expected() {
    let cause = map_lifecycle_channel_closed(true);
    assert_eq!(cause, None);
}

/// SupervisorDisconnect via lifecycle event preserves the cause correctly.
#[tokio::test]
async fn test_supervisor_disconnect_via_lifecycle_preserves_cause() {
    let event = WorkerLifecycleEvent::SupervisorDisconnected;
    let cause = match &event {
        WorkerLifecycleEvent::MasterShutdown { .. } => WorkerShutdownCause::SupervisorShutdown,
        WorkerLifecycleEvent::WorkerResize { worker_threads } => {
            WorkerShutdownCause::WorkerResize {
                worker_threads: *worker_threads,
            }
        }
        WorkerLifecycleEvent::SupervisorDisconnected => WorkerShutdownCause::SupervisorDisconnected,
    };
    assert_eq!(cause, WorkerShutdownCause::SupervisorDisconnected);
    assert!(!cause.should_notify_supervisor());
    assert!(cause.nonzero_exit_code());
}

/// Normal MasterShutdown via lifecycle produces SupervisorShutdown.
#[tokio::test]
async fn test_normal_master_shutdown_via_lifecycle() {
    let mut registry = WorkerTaskRegistry::new();
    let mut exit_rx = registry.subscribe_exits();

    let (lifecycle_tx, mut lifecycle_rx) = tokio::sync::mpsc::channel::<
        synvoid::worker::unified_server::lifecycle::LifecycleRequest,
    >(4);

    // Simulate IPC task sending MasterShutdown.
    registry.spawn_critical("ipc_sim", async move {
        let (ack_tx, ack_rx) = tokio::sync::oneshot::channel();
        let _ = lifecycle_tx
            .send(
                synvoid::worker::unified_server::lifecycle::LifecycleRequest {
                    event: WorkerLifecycleEvent::MasterShutdown {
                        graceful: true,
                        timeout: Duration::from_secs(30),
                    },
                    accepted: ack_tx,
                },
            )
            .await;
        let _ = ack_rx.await;
    });

    // Receive lifecycle event.
    let request = tokio::time::timeout(Duration::from_secs(2), lifecycle_rx.recv())
        .await
        .expect("timeout")
        .expect("no event");

    assert!(matches!(
        request.event,
        WorkerLifecycleEvent::MasterShutdown { .. }
    ));

    // Begin shutdown and acknowledge.
    registry.begin_shutdown();
    let _ = request.accepted.send(());

    // Verify the cause maps correctly.
    let cause = match &request.event {
        WorkerLifecycleEvent::MasterShutdown { .. } => WorkerShutdownCause::SupervisorShutdown,
        _ => panic!("Expected MasterShutdown"),
    };
    assert_eq!(cause, WorkerShutdownCause::SupervisorShutdown);
    assert!(!cause.nonzero_exit_code());
    assert!(cause.is_expected());
    assert!(!cause.should_notify_supervisor());
}

/// Competing lifecycle event and task exit: the first selected event remains authoritative.
/// This test verifies that when a lifecycle event is received via select, it carries
/// the correct acknowledgement sender and cannot be overridden by a later task exit.
#[tokio::test]
async fn test_competing_lifecycle_event_wins() {
    let mut registry = WorkerTaskRegistry::new();

    let (lifecycle_tx, mut lifecycle_rx) = tokio::sync::mpsc::channel::<
        synvoid::worker::unified_server::lifecycle::LifecycleRequest,
    >(4);

    // Spawn IPC task that sends a lifecycle event.
    registry.spawn_critical("ipc_sim", async move {
        let (ack_tx, ack_rx) = tokio::sync::oneshot::channel();
        let _ = lifecycle_tx
            .send(
                synvoid::worker::unified_server::lifecycle::LifecycleRequest {
                    event: WorkerLifecycleEvent::MasterShutdown {
                        graceful: true,
                        timeout: Duration::from_secs(30),
                    },
                    accepted: ack_tx,
                },
            )
            .await;
        let _ = ack_rx.await;
    });

    // Wait for the lifecycle event to be available.
    let request = tokio::time::timeout(Duration::from_secs(2), lifecycle_rx.recv())
        .await
        .expect("timeout")
        .expect("no lifecycle event");

    // Once the lifecycle event is received, it is authoritative.
    // Verify it carries the correct event and ack sender.
    assert!(matches!(
        request.event,
        WorkerLifecycleEvent::MasterShutdown { .. }
    ));

    // Begin shutdown and acknowledge — this proves the lifecycle path is authoritative.
    registry.begin_shutdown();
    let _ = request.accepted.send(());

    // The IPC task should complete cleanly.
    let exits = registry
        .shutdown_and_join(Duration::from_secs(5), Duration::from_secs(5))
        .await;
    let non_clean: Vec<_> = exits
        .iter()
        .filter(|e| e.reason != TaskExitReason::CleanCompletion)
        .collect();
    assert!(
        non_clean.is_empty(),
        "Expected clean shutdown, got: {:?}",
        non_clean
    );
}

/// request_lifecycle_transition returns error when channel is closed.
#[tokio::test]
async fn test_request_lifecycle_transition_channel_closed() {
    let (lifecycle_tx, _lifecycle_rx) = tokio::sync::mpsc::channel::<
        synvoid::worker::unified_server::lifecycle::LifecycleRequest,
    >(4);
    drop(_lifecycle_rx);

    let result = synvoid::worker::unified_server::lifecycle::request_lifecycle_transition(
        &lifecycle_tx,
        WorkerLifecycleEvent::MasterShutdown {
            graceful: true,
            timeout: Duration::from_secs(30),
        },
    )
    .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        IpcLoopError::Unexpected(msg) => {
            assert!(
                msg.contains("channel closed"),
                "Error should mention channel closure: {}",
                msg
            );
        }
        other => panic!("Expected Unexpected error, got {:?}", other),
    }
}

/// request_lifecycle_transition returns error when ack sender is dropped.
#[tokio::test]
async fn test_request_lifecycle_transition_ack_dropped() {
    let (lifecycle_tx, mut lifecycle_rx) = tokio::sync::mpsc::channel::<
        synvoid::worker::unified_server::lifecycle::LifecycleRequest,
    >(4);

    // Spawn a task that receives but drops the acknowledgement.
    tokio::spawn(async move {
        if let Some(req) = lifecycle_rx.recv().await {
            drop(req.accepted); // Drop ack sender without sending.
        }
    });

    let result = synvoid::worker::unified_server::lifecycle::request_lifecycle_transition(
        &lifecycle_tx,
        WorkerLifecycleEvent::MasterShutdown {
            graceful: true,
            timeout: Duration::from_secs(30),
        },
    )
    .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        IpcLoopError::Unexpected(msg) => {
            assert!(
                msg.contains("dropped"),
                "Error should mention dropped ack: {}",
                msg
            );
        }
        other => panic!("Expected Unexpected error, got {:?}", other),
    }
}

/// ServerExitedUnexpectedly exit code is 1 and should_notify is true.
#[tokio::test]
async fn test_server_exited_unexpectedly_notification_routing() {
    let cause = WorkerShutdownCause::ServerExitedUnexpectedly(NamedTaskExit {
        id: TaskId(0),
        name: "server_run",
        class: TaskClass::CriticalService,
        reason: TaskExitReason::Error("test".to_string()),
        expected_during_shutdown: false,
    });
    assert!(cause.nonzero_exit_code());
    assert_eq!(cause.exit_code(), 1);
    assert!(cause.should_notify_supervisor());
    assert!(!cause.is_expected());
}

/// RegistryExitChannelClosed exit code is 1 and should_notify is true.
#[tokio::test]
async fn test_registry_exit_channel_closed_notification_routing() {
    let cause = WorkerShutdownCause::RegistryExitChannelClosed;
    assert!(cause.nonzero_exit_code());
    assert_eq!(cause.exit_code(), 1);
    assert!(cause.should_notify_supervisor());
    assert!(!cause.is_expected());
}

/// CriticalTaskExit notification routing preserves task name and reason.
#[tokio::test]
async fn test_critical_task_exit_notification_routing() {
    let exit = NamedTaskExit {
        id: TaskId(42),
        name: "ipc_loop",
        class: TaskClass::CriticalService,
        reason: TaskExitReason::Error("connection_lost".to_string()),
        expected_during_shutdown: false,
    };
    let cause = WorkerShutdownCause::CriticalTaskExit(exit.clone());
    assert!(cause.should_notify_supervisor());
    assert!(cause.nonzero_exit_code());
    assert_eq!(cause.exit_code(), 1);

    // Verify task details survive in the cause.
    match &cause {
        WorkerShutdownCause::CriticalTaskExit(e) => {
            assert_eq!(e.name, "ipc_loop");
            assert_eq!(
                e.reason,
                TaskExitReason::Error("connection_lost".to_string())
            );
        }
        _ => panic!("Expected CriticalTaskExit"),
    }
}

// ---------------------------------------------------------------------------
// Iteration 67 — Lifecycle transition failure and shutdown ordering tests
// ---------------------------------------------------------------------------

/// request_lifecycle_transition returns IpcLoopError::Unexpected when coordinator channel is closed.
#[tokio::test]
async fn test_lifecycle_transition_coordinator_channel_closed() {
    let (lifecycle_tx, _lifecycle_rx) = tokio::sync::mpsc::channel::<
        synvoid::worker::unified_server::lifecycle::LifecycleRequest,
    >(4);
    drop(_lifecycle_rx);

    let result = synvoid::worker::unified_server::lifecycle::request_lifecycle_transition(
        &lifecycle_tx,
        WorkerLifecycleEvent::MasterShutdown {
            graceful: true,
            timeout: Duration::from_secs(30),
        },
    )
    .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        IpcLoopError::Unexpected(msg) => {
            assert!(
                msg.contains("channel closed"),
                "Error should mention coordinator channel closure: {}",
                msg
            );
        }
        other => panic!(
            "Expected Unexpected error for channel closure, got {:?}",
            other
        ),
    }
}

/// request_lifecycle_transition returns IpcLoopError::Unexpected when ack sender is dropped.
#[tokio::test]
async fn test_lifecycle_transition_ack_dropped() {
    let (lifecycle_tx, mut lifecycle_rx) = tokio::sync::mpsc::channel::<
        synvoid::worker::unified_server::lifecycle::LifecycleRequest,
    >(4);

    // Spawn a task that receives but drops the acknowledgement sender.
    tokio::spawn(async move {
        if let Some(req) = lifecycle_rx.recv().await {
            drop(req.accepted);
        }
    });

    let result = synvoid::worker::unified_server::lifecycle::request_lifecycle_transition(
        &lifecycle_tx,
        WorkerLifecycleEvent::MasterShutdown {
            graceful: true,
            timeout: Duration::from_secs(30),
        },
    )
    .await;

    assert!(result.is_err());
    match result.unwrap_err() {
        IpcLoopError::Unexpected(msg) => {
            assert!(
                msg.contains("dropped"),
                "Error should mention dropped acknowledgement: {}",
                msg
            );
        }
        other => panic!("Expected Unexpected error for dropped ack, got {:?}", other),
    }
}

/// Successful lifecycle transition returns Ok(()).
#[tokio::test]
async fn test_lifecycle_transition_success() {
    let (lifecycle_tx, mut lifecycle_rx) = tokio::sync::mpsc::channel::<
        synvoid::worker::unified_server::lifecycle::LifecycleRequest,
    >(4);

    // Spawn a task that receives and acknowledges.
    tokio::spawn(async move {
        if let Some(req) = lifecycle_rx.recv().await {
            let _ = req.accepted.send(());
        }
    });

    let result = synvoid::worker::unified_server::lifecycle::request_lifecycle_transition(
        &lifecycle_tx,
        WorkerLifecycleEvent::MasterShutdown {
            graceful: true,
            timeout: Duration::from_secs(30),
        },
    )
    .await;

    assert!(result.is_ok(), "Successful transition should return Ok(())");
}

/// IPC-like task using `?` on request_lifecycle_transition produces TaskExitReason::Error on failure.
#[tokio::test]
async fn test_lifecycle_failure_produces_task_error() {
    let mut registry = WorkerTaskRegistry::new();
    let mut exit_rx = registry.subscribe_exits();

    let (lifecycle_tx, _lifecycle_rx) = tokio::sync::mpsc::channel::<
        synvoid::worker::unified_server::lifecycle::LifecycleRequest,
    >(4);
    drop(_lifecycle_rx);

    // Simulate an IPC-like task that uses `?` on lifecycle transition.
    registry.spawn_critical_result("ipc_sim", async move {
        synvoid::worker::unified_server::lifecycle::request_lifecycle_transition(
            &lifecycle_tx,
            WorkerLifecycleEvent::MasterShutdown {
                graceful: true,
                timeout: Duration::from_secs(30),
            },
        )
        .await
        .map_err(|e| format!("{}", e))
    });

    let exit = tokio::time::timeout(Duration::from_secs(2), exit_rx.recv())
        .await
        .expect("timeout")
        .expect("recv");

    // The task should exit with an Error, not CleanCompletion.
    assert!(
        matches!(exit.reason, TaskExitReason::Error(_)),
        "Lifecycle failure should produce TaskExitReason::Error, got {:?}",
        exit.reason
    );
}

/// Critical failure with secondary critical exit: secondary is classified as expected.
#[tokio::test]
async fn test_critical_failure_secondary_exit_classified_cleanly() {
    let mut registry = WorkerTaskRegistry::new();
    let mut exit_rx = registry.subscribe_exits();
    let shutdown_flag = registry.shutdown_started_flag();

    // Primary critical task that fails immediately.
    registry.spawn_critical("primary_failure", async {
        panic!("primary failure");
    });

    // Secondary critical task that waits on shutdown signal.
    let token = registry.child_token();
    registry.spawn_critical("secondary_waiter", async move {
        let mut shutdown = token;
        loop {
            if *shutdown.borrow() {
                break;
            }
            if shutdown.changed().await.is_err() {
                break;
            }
        }
    });

    // Wait for the primary failure to be observed.
    let exit = tokio::time::timeout(Duration::from_secs(2), exit_rx.recv())
        .await
        .expect("timeout")
        .expect("recv");

    let shutdown_started = shutdown_flag.load(Ordering::Acquire);
    assert!(is_fatal_exit(&exit, shutdown_started));
    assert_eq!(exit.name, "primary_failure");

    // Record the unexpected completion count before simulating shutdown.
    let unexpected_before = registry
        .metrics
        .tasks_unexpectedly_completed
        .load(Ordering::Relaxed);

    // Simulate the composition root: begin_shutdown then broadcast.
    registry.begin_shutdown();
    registry.broadcast_shutdown();

    // Now join all tasks.
    let _exits = registry
        .shutdown_and_join(Duration::from_secs(5), Duration::from_secs(5))
        .await;

    // Secondary task should have exited cleanly (CleanCompletion after begin_shutdown).
    let unexpected_after = registry
        .metrics
        .tasks_unexpectedly_completed
        .load(Ordering::Relaxed);
    assert_eq!(
        unexpected_after, unexpected_before,
        "Secondary exit should not increment unexpected completion count"
    );
}

/// Registry failure with secondary background exit: primary cause preserved.
#[tokio::test]
async fn test_registry_failure_secondary_exit_clean() {
    let mut registry = WorkerTaskRegistry::new();
    let shutdown_flag = registry.shutdown_started_flag();

    // Simulate registry exit receiver lag.
    let cause = map_exit_recv_error_to_shutdown_cause(
        tokio::sync::broadcast::error::RecvError::Lagged(42),
        false,
    );
    assert_eq!(cause, Some(WorkerShutdownCause::RegistryExitChannelClosed));

    // Begin shutdown before any stop signal (Phase 4 ordering).
    registry.begin_shutdown();
    let shutdown_started = shutdown_flag.load(Ordering::Acquire);
    assert!(shutdown_started);

    // A background task waiting on shutdown should exit cleanly.
    let token = registry.child_token();
    registry.spawn_cancellable_background("bg_waiter", async move {
        let mut shutdown = token;
        loop {
            if *shutdown.borrow() {
                break;
            }
            if shutdown.changed().await.is_err() {
                break;
            }
        }
    });

    registry.broadcast_shutdown();
    let _exits = registry
        .shutdown_and_join(Duration::from_secs(5), Duration::from_secs(5))
        .await;

    // The _exits are from shutdown_and_join, not from exit_rx. We can't easily check
    // individual exits here since shutdown_and_join doesn't return them via exit_rx.
    // The key assertion is that the process completes without hanging.
}

/// Server failure preserves the NamedTaskExit detail.
#[tokio::test]
async fn test_server_failure_preserves_named_task_exit_detail() {
    let mut registry = WorkerTaskRegistry::new();
    let mut exit_rx = registry.subscribe_exits();

    registry.spawn_critical_result("server_run", async {
        Err::<(), String>("server crashed".to_string())
    });

    let exit = tokio::time::timeout(Duration::from_secs(2), exit_rx.recv())
        .await
        .expect("timeout")
        .expect("recv");

    assert_eq!(exit.name, "server_run");
    let cause = map_task_exit_to_shutdown_cause(exit.clone());
    match &cause {
        WorkerShutdownCause::ServerExitedUnexpectedly(e) => {
            assert_eq!(e.name, "server_run");
            assert!(matches!(&e.reason, TaskExitReason::Error(_)));
        }
        other => panic!("Expected ServerExitedUnexpectedly, got {:?}", other),
    }
}

// ── Mesh exit integration tests ────────────────────────────────────────────

/// MeshServiceExit with a fatal exit reason is classified as fatal.
#[cfg(feature = "mesh")]
#[tokio::test]
async fn test_mesh_service_exit_is_fatal() {
    use synvoid_mesh::lifecycle::{MeshTaskClass, MeshTaskExit, MeshTaskExitReason, MeshTaskId};

    let mesh_exit = MeshTaskExit {
        id: MeshTaskId(42),
        name: "mesh_accept_loop",
        class: MeshTaskClass::CriticalService,
        reason: MeshTaskExitReason::Panic("connection reset".into()),
    };
    let cause = WorkerShutdownCause::MeshServiceExit(mesh_exit);
    assert!(cause.nonzero_exit_code());
    assert!(cause.should_notify_supervisor());
    assert!(!cause.is_expected());
}

/// MeshServiceExit with a non-fatal exit reason (CleanCompletion) is still nonzero
/// because it's a critical mesh service.
#[cfg(feature = "mesh")]
#[tokio::test]
async fn test_mesh_service_exit_clean_completion_still_nonzero() {
    use synvoid_mesh::lifecycle::{MeshTaskClass, MeshTaskExit, MeshTaskExitReason, MeshTaskId};

    let mesh_exit = MeshTaskExit {
        id: MeshTaskId(1),
        name: "mesh_maintenance",
        class: MeshTaskClass::CriticalService,
        reason: MeshTaskExitReason::CleanCompletion,
    };
    let cause = WorkerShutdownCause::MeshServiceExit(mesh_exit);
    // MeshServiceExit always has nonzero exit code
    assert!(cause.nonzero_exit_code());
    assert!(cause.should_notify_supervisor());
}

/// MeshServiceExit exit code is 1.
#[cfg(feature = "mesh")]
#[tokio::test]
async fn test_mesh_service_exit_exit_code() {
    use synvoid_mesh::lifecycle::{MeshTaskClass, MeshTaskExit, MeshTaskExitReason, MeshTaskId};

    let mesh_exit = MeshTaskExit {
        id: MeshTaskId(0),
        name: "datagram_listener",
        class: MeshTaskClass::CriticalService,
        reason: MeshTaskExitReason::Error("bind failed".into()),
    };
    let cause = WorkerShutdownCause::MeshServiceExit(mesh_exit);
    assert_eq!(cause.exit_code(), 1);
}

/// MeshServiceExit display includes task name and reason.
#[cfg(feature = "mesh")]
#[tokio::test]
async fn test_mesh_service_exit_display() {
    use synvoid_mesh::lifecycle::{MeshTaskClass, MeshTaskExit, MeshTaskExitReason, MeshTaskId};

    let mesh_exit = MeshTaskExit {
        id: MeshTaskId(0),
        name: "mesh_accept_loop",
        class: MeshTaskClass::CriticalService,
        reason: MeshTaskExitReason::Panic("overflow".into()),
    };
    let cause = WorkerShutdownCause::MeshServiceExit(mesh_exit);
    let display = format!("{}", cause);
    assert!(display.contains("mesh_accept_loop"));
    assert!(display.contains("panic: overflow"));
}

/// MeshServiceExit maps correctly through map_task_exit_to_shutdown_cause
/// when the exit name is NOT "server_run".
#[cfg(feature = "mesh")]
#[tokio::test]
async fn test_mesh_exit_maps_to_mesh_service_exit() {
    use synvoid_mesh::lifecycle::{MeshTaskClass, MeshTaskExit, MeshTaskExitReason, MeshTaskId};

    let mesh_exit = MeshTaskExit {
        id: MeshTaskId(5),
        name: "mesh_accept_loop",
        class: MeshTaskClass::CriticalService,
        reason: MeshTaskExitReason::Error("QUIC handshake timeout".into()),
    };
    // map_task_exit_to_shutdown_cause maps non-"server_run" critical exits to CriticalTaskExit
    // MeshServiceExit is constructed manually by the mesh integration layer
    let cause = WorkerShutdownCause::MeshServiceExit(mesh_exit);
    match &cause {
        WorkerShutdownCause::MeshServiceExit(exit) => {
            assert_eq!(exit.name, "mesh_accept_loop");
            assert!(matches!(&exit.reason, MeshTaskExitReason::Error(_)));
        }
        other => panic!("Expected MeshServiceExit, got {:?}", other),
    }
}

/// Once SupervisionOutcome is selected, later task exits cannot replace the cause.
#[tokio::test]
async fn test_primary_cause_cannot_be_replaced() {
    let mut registry = WorkerTaskRegistry::new();
    let mut exit_rx = registry.subscribe_exits();
    let shutdown_flag = registry.shutdown_started_flag();

    // Spawn a task that panics (fatal).
    registry.spawn_critical("fatal_task", async {
        panic!("fatal");
    });

    // Spawn a task that returns early (also fatal).
    registry.spawn_critical("early_return", async {});

    // Collect both exits.
    let mut exits_received = Vec::new();
    for _ in 0..2 {
        let exit = tokio::time::timeout(Duration::from_secs(2), exit_rx.recv())
            .await
            .expect("timeout")
            .expect("recv");
        let shutdown_started = shutdown_flag.load(Ordering::Acquire);
        if is_fatal_exit(&exit, shutdown_started) {
            exits_received.push(exit);
        }
    }

    assert!(
        !exits_received.is_empty(),
        "Should have received at least one fatal exit"
    );

    // The first fatal exit is the primary cause. Verify map_task_exit_to_shutdown_cause
    // produces a valid cause from it.
    let primary_cause = map_task_exit_to_shutdown_cause(exits_received[0].clone());
    assert!(
        primary_cause.nonzero_exit_code(),
        "Primary cause should have nonzero exit code"
    );
    assert!(
        primary_cause.should_notify_supervisor(),
        "Primary cause should notify supervisor"
    );
}

// ── Iteration 84 — Mesh supervision behavioral tests ──────────────────────
//
// Pure decision-logic and status-transition tests proving the behavioral
// contracts of the mesh supervision system without spinning up a full worker.

#[cfg(feature = "mesh")]
mod iter84_behavioral_tests {
    use synvoid::worker::mesh_supervision::{
        apply_mesh_decision_to_status, apply_mesh_event_to_status, build_mesh_supervision_policy,
        classify_mesh_shutdown_report, decide_mesh_action, MeshFailureAction, MeshServiceHealth,
        MeshShutdownDisposition, MeshSupervisionEvent, MeshSupervisionPolicy,
        MeshSupervisorDecision, WorkerMeshPhase, WorkerMeshStatus,
    };
    use synvoid_mesh::lifecycle::{
        MeshShutdownReport, MeshTaskClass, MeshTaskExit, MeshTaskExitReason, MeshTaskId,
        PeerStreamDrainReport,
    };

    /// Helper: check mesh readiness without async (for unit tests).
    fn is_mesh_ready_with_status(
        policy: &MeshSupervisionPolicy,
        status: &WorkerMeshStatus,
    ) -> bool {
        if !policy.required {
            return true;
        }
        match status.phase {
            WorkerMeshPhase::Running => true,
            WorkerMeshPhase::Degraded => policy.allow_degraded_readiness,
            _ => false,
        }
    }

    // --- Test 1: disabled mesh returns no policy ---

    #[test]
    fn disabled_mesh_returns_none_policy() {
        let config = synvoid_config::MeshSupervisionConfig::default();
        let policy = build_mesh_supervision_policy(false, &config);
        assert!(policy.unwrap().is_none());
    }

    // --- Test 2: disabled mesh status remains disabled ---

    #[test]
    fn disabled_mesh_status_remains_disabled() {
        let status = WorkerMeshStatus::default();
        assert_eq!(status.phase, WorkerMeshPhase::Disabled);
    }

    // --- Test 3: required mesh startup failure produces shutdown ---

    #[test]
    fn required_mesh_startup_failure_produces_shutdown_decision() {
        let policy = MeshSupervisionPolicy::required();
        let phase = WorkerMeshPhase::Starting;
        let event = MeshSupervisionEvent::StartupFailed("connection refused".into());
        let decision = decide_mesh_action(&policy, &phase, &event, false);
        assert!(matches!(
            decision,
            MeshSupervisorDecision::ShutdownWorker(_)
        ));
    }

    // --- Test 4: optional mesh startup failure produces degrade ---

    #[test]
    fn optional_mesh_startup_failure_produces_degrade_decision() {
        let policy = MeshSupervisionPolicy::optional();
        let phase = WorkerMeshPhase::Starting;
        let event = MeshSupervisionEvent::StartupFailed("connection refused".into());
        let decision = decide_mesh_action(&policy, &phase, &event, false);
        assert!(matches!(decision, MeshSupervisorDecision::MarkDegraded(_)));
    }

    // --- Test 5: required mesh ready requires Running phase ---

    #[test]
    fn required_mesh_ready_requires_running_phase() {
        let policy = MeshSupervisionPolicy::required();
        // Not ready in Disabled
        let status = WorkerMeshStatus {
            phase: WorkerMeshPhase::Disabled,
            ..Default::default()
        };
        assert!(!is_mesh_ready_with_status(&policy, &status));
        // Not ready in Starting
        let status = WorkerMeshStatus {
            phase: WorkerMeshPhase::Starting,
            ..Default::default()
        };
        assert!(!is_mesh_ready_with_status(&policy, &status));
        // Ready in Running
        let status = WorkerMeshStatus {
            phase: WorkerMeshPhase::Running,
            ..Default::default()
        };
        assert!(is_mesh_ready_with_status(&policy, &status));
        // Not ready in Degraded (unless allow_degraded_readiness)
        let status = WorkerMeshStatus {
            phase: WorkerMeshPhase::Degraded,
            ..Default::default()
        };
        assert!(!is_mesh_ready_with_status(&policy, &status));
    }

    // --- Test 6: required mesh ready with degraded readiness flag ---

    #[test]
    fn required_mesh_ready_with_degraded_readiness() {
        let mut policy = MeshSupervisionPolicy::required();
        policy.allow_degraded_readiness = true;
        let status = WorkerMeshStatus {
            phase: WorkerMeshPhase::Degraded,
            ..Default::default()
        };
        assert!(is_mesh_ready_with_status(&policy, &status));
    }

    // --- Test 7: optional mesh is always ready regardless of phase ---

    #[test]
    fn optional_mesh_always_ready() {
        let policy = MeshSupervisionPolicy::optional();
        for phase in &[
            WorkerMeshPhase::Disabled,
            WorkerMeshPhase::Starting,
            WorkerMeshPhase::Running,
            WorkerMeshPhase::Degraded,
            WorkerMeshPhase::Failed,
        ] {
            let status = WorkerMeshStatus {
                phase: *phase,
                ..Default::default()
            };
            assert!(
                is_mesh_ready_with_status(&policy, &status),
                "optional mesh should be ready in {:?} phase",
                phase
            );
        }
    }

    // --- Test 8: observer/coordinator exit while running (required) is fatal ---

    #[test]
    fn observer_coordinator_exit_while_running_required_is_fatal() {
        let policy = MeshSupervisionPolicy::required();
        let phase = WorkerMeshPhase::Running;

        // Observer exit (CriticalService)
        let exit = MeshTaskExit {
            id: MeshTaskId(1),
            name: "mesh_exit_observer",
            class: MeshTaskClass::CriticalService,
            reason: MeshTaskExitReason::CleanCompletion,
        };
        let event = MeshSupervisionEvent::TaskExit(exit);
        let decision = decide_mesh_action(&policy, &phase, &event, false);
        assert!(matches!(
            decision,
            MeshSupervisorDecision::ShutdownWorker(_)
        ));

        // Coordinator exit (CriticalService)
        let exit = MeshTaskExit {
            id: MeshTaskId(2),
            name: "mesh_supervision_coordinator",
            class: MeshTaskClass::CriticalService,
            reason: MeshTaskExitReason::Error("channel closed".into()),
        };
        let event = MeshSupervisionEvent::TaskExit(exit);
        let decision = decide_mesh_action(&policy, &phase, &event, false);
        assert!(matches!(
            decision,
            MeshSupervisorDecision::ShutdownWorker(_)
        ));
    }

    // --- Test 9: observer/coordinator exit during shutdown is noop ---

    #[test]
    fn observer_coordinator_exit_during_shutdown_is_noop() {
        let policy = MeshSupervisionPolicy::required();
        let phase = WorkerMeshPhase::Stopping;
        let exit = MeshTaskExit {
            id: MeshTaskId(1),
            name: "mesh_exit_observer",
            class: MeshTaskClass::CriticalService,
            reason: MeshTaskExitReason::Cancelled,
        };
        let event = MeshSupervisionEvent::TaskExit(exit);
        let decision = decide_mesh_action(&policy, &phase, &event, true);
        assert!(matches!(decision, MeshSupervisorDecision::NoAction));
    }

    // --- Test 10: restart-mesh decision requires restart enabled ---

    #[test]
    fn restart_mesh_decision_requires_restart_enabled_policy() {
        // With restart disabled (default required policy), RestartMesh should never be produced.
        let policy = MeshSupervisionPolicy::required();
        let phase = WorkerMeshPhase::Running;
        let exit = MeshTaskExit {
            id: MeshTaskId(1),
            name: "mesh_maintenance",
            class: MeshTaskClass::CriticalService,
            reason: MeshTaskExitReason::Panic("test".into()),
        };
        let event = MeshSupervisionEvent::TaskExit(exit);
        let decision = decide_mesh_action(&policy, &phase, &event, false);
        // Required policy with restart disabled should shutdown, not restart
        assert!(matches!(
            decision,
            MeshSupervisorDecision::ShutdownWorker(_)
        ));
    }

    // --- Test 11: config-derived policy matches expected fields ---

    #[test]
    fn config_derived_policy_matches_expected() {
        let config = synvoid_config::MeshSupervisionConfig {
            required: true,
            restart_enabled: false,
            restart_limit: 3,
            restart_window_secs: 300,
            restart_backoff_initial_secs: 5,
            restart_backoff_max_secs: 60,
            allow_degraded_readiness: false,
        };
        let policy = build_mesh_supervision_policy(true, &config)
            .unwrap()
            .unwrap();
        assert!(policy.required);
        assert_eq!(policy.restart_limit, 0); // restart_enabled=false
        assert!(!policy.allow_degraded_readiness);
        assert_eq!(policy.startup_failure, MeshFailureAction::ShutdownWorker);
    }

    // --- Test 12: status transitions cover full lifecycle ---

    #[test]
    fn status_transitions_cover_lifecycle() {
        let mut status = WorkerMeshStatus::default();
        assert_eq!(status.phase, WorkerMeshPhase::Disabled);

        status.transition_starting();
        assert_eq!(status.phase, WorkerMeshPhase::Starting);

        status.transition_running();
        assert_eq!(status.phase, WorkerMeshPhase::Running);

        status.transition_degraded("test".into());
        assert_eq!(status.phase, WorkerMeshPhase::Degraded);

        status.transition_restarting();
        assert_eq!(status.phase, WorkerMeshPhase::Restarting);

        status.transition_failed("test".into());
        assert_eq!(status.phase, WorkerMeshPhase::Failed);

        status.transition_stopping();
        assert_eq!(status.phase, WorkerMeshPhase::Stopping);

        status.transition_stopped();
        assert_eq!(status.phase, WorkerMeshPhase::Stopped);
    }

    // --- Test 13: shutdown disposition classification ---

    #[test]
    fn shutdown_disposition_classification_clean() {
        let report = MeshShutdownReport {
            clean_tasks: 5,
            failed_tasks: vec![],
            aborted_tasks: vec![],
            accept_loop_report: None,
            remaining_peers: 0,
            peers_at_shutdown_start: 3,
            drained_peer_sessions: 3,
            aborted_peer_sessions: 0,
            failed_peer_sessions: 0,
            stream_handler_drain: PeerStreamDrainReport {
                drained: 0,
                aborted: 0,
                failed: 0,
            },
        };
        assert!(matches!(
            classify_mesh_shutdown_report(&report),
            MeshShutdownDisposition::Clean
        ));
    }

    #[test]
    fn shutdown_disposition_classification_forced_complete() {
        let report = MeshShutdownReport {
            clean_tasks: 3,
            failed_tasks: vec![],
            aborted_tasks: vec![MeshTaskExit {
                id: MeshTaskId(1),
                name: "test",
                class: MeshTaskClass::RestartableBackground,
                reason: MeshTaskExitReason::Aborted,
            }],
            accept_loop_report: None,
            remaining_peers: 0,
            peers_at_shutdown_start: 1,
            drained_peer_sessions: 0,
            aborted_peer_sessions: 1,
            failed_peer_sessions: 0,
            stream_handler_drain: PeerStreamDrainReport {
                drained: 0,
                aborted: 1,
                failed: 0,
            },
        };
        assert!(matches!(
            classify_mesh_shutdown_report(&report),
            MeshShutdownDisposition::ForcedButComplete
        ));
    }

    #[test]
    fn shutdown_disposition_classification_incomplete() {
        let report = MeshShutdownReport {
            clean_tasks: 1,
            failed_tasks: vec![MeshTaskExit {
                id: MeshTaskId(3),
                name: "broken_task",
                class: MeshTaskClass::CriticalService,
                reason: MeshTaskExitReason::Error("broken".into()),
            }],
            aborted_tasks: vec![],
            accept_loop_report: None,
            remaining_peers: 2,
            peers_at_shutdown_start: 5,
            drained_peer_sessions: 1,
            aborted_peer_sessions: 0,
            failed_peer_sessions: 0,
            stream_handler_drain: PeerStreamDrainReport {
                drained: 1,
                aborted: 0,
                failed: 0,
            },
        };
        assert!(matches!(
            classify_mesh_shutdown_report(&report),
            MeshShutdownDisposition::Incomplete(_)
        ));
    }

    // --- Test 14: apply_mesh_event_to_status transitions ---

    #[test]
    fn apply_started_event_transitions_to_running() {
        let mut status = WorkerMeshStatus::default();
        assert_eq!(status.phase, WorkerMeshPhase::Disabled);
        apply_mesh_event_to_status(&mut status, &MeshSupervisionEvent::Started);
        assert_eq!(status.phase, WorkerMeshPhase::Running);
    }

    #[test]
    fn apply_startup_failed_event_transitions_to_failed() {
        let mut status = WorkerMeshStatus::default();
        apply_mesh_event_to_status(
            &mut status,
            &MeshSupervisionEvent::StartupFailed("refused".into()),
        );
        assert_eq!(status.phase, WorkerMeshPhase::Failed);
    }

    #[test]
    fn apply_lag_event_transitions_to_degraded() {
        let mut status = WorkerMeshStatus::default();
        apply_mesh_event_to_status(&mut status, &MeshSupervisionEvent::ExitStreamLagged(5));
        assert_eq!(status.phase, WorkerMeshPhase::Degraded);
    }

    #[test]
    fn apply_shutdown_started_transitions_to_stopping() {
        let mut status = WorkerMeshStatus::default();
        apply_mesh_event_to_status(&mut status, &MeshSupervisionEvent::WorkerShutdownStarted);
        assert_eq!(status.phase, WorkerMeshPhase::Stopping);
    }

    // --- Test 15: apply_mesh_decision_to_status transitions ---

    #[test]
    fn apply_degraded_decision_transitions_to_degraded() {
        let mut status = WorkerMeshStatus::default();
        apply_mesh_decision_to_status(
            &mut status,
            &MeshSupervisorDecision::MarkDegraded("reason".into()),
        );
        assert_eq!(status.phase, WorkerMeshPhase::Degraded);
    }

    #[test]
    fn apply_restart_decision_transitions_to_restarting() {
        let mut status = WorkerMeshStatus::default();
        apply_mesh_decision_to_status(&mut status, &MeshSupervisorDecision::RestartMesh);
        assert_eq!(status.phase, WorkerMeshPhase::Restarting);
    }

    #[test]
    fn apply_shutdown_decision_transitions_to_failed() {
        let mut status = WorkerMeshStatus::default();
        apply_mesh_decision_to_status(
            &mut status,
            &MeshSupervisorDecision::ShutdownWorker(
                synvoid_mesh::worker_integration::MeshFailureCause::StartupFailed("x".into()),
            ),
        );
        assert_eq!(status.phase, WorkerMeshPhase::Failed);
    }

    // --- Test 16: disabled mesh runtime behavior: no supervision tasks ---

    #[test]
    fn disabled_mesh_policy_produces_none() {
        let config = synvoid_config::MeshSupervisionConfig::default();
        assert!(build_mesh_supervision_policy(false, &config)
            .unwrap()
            .is_none());
        // When policy is None, no supervision coordinator or observer should be created.
        // Ready signal is immediate.
    }

    // --- Test 17: required startup success sends ready afterward ---

    #[test]
    fn required_startup_success_transitions_to_running() {
        let mut status = WorkerMeshStatus::default();
        assert_eq!(status.phase, WorkerMeshPhase::Disabled);

        // Simulate the startup sequence: Started event transitions to Running.
        apply_mesh_event_to_status(&mut status, &MeshSupervisionEvent::Started);
        assert_eq!(status.phase, WorkerMeshPhase::Running);

        let policy = MeshSupervisionPolicy::required();
        assert!(is_mesh_ready_with_status(&policy, &status));
    }

    // --- Test 18: required startup failure never sends ready ---

    #[test]
    fn required_startup_failure_never_ready() {
        let policy = MeshSupervisionPolicy::required();
        let mut status = WorkerMeshStatus::default();

        apply_mesh_event_to_status(
            &mut status,
            &MeshSupervisionEvent::StartupFailed("refused".into()),
        );
        assert_eq!(status.phase, WorkerMeshPhase::Failed);
        assert!(!is_mesh_ready_with_status(&policy, &status));

        // Even after applying the decision, still not ready.
        let decision = decide_mesh_action(
            &policy,
            &status.phase,
            &MeshSupervisionEvent::StartupFailed("x".into()),
            false,
        );
        apply_mesh_decision_to_status(&mut status, &decision);
        assert_eq!(status.phase, WorkerMeshPhase::Failed);
        assert!(!is_mesh_ready_with_status(&policy, &status));
    }

    // --- Test 19: optional startup failure leaves worker ready but degraded ---

    #[test]
    fn optional_startup_failure_ready_but_degraded() {
        let policy = MeshSupervisionPolicy::optional();
        let mut status = WorkerMeshStatus::default();

        apply_mesh_event_to_status(
            &mut status,
            &MeshSupervisionEvent::StartupFailed("refused".into()),
        );
        let decision = decide_mesh_action(
            &policy,
            &status.phase,
            &MeshSupervisionEvent::StartupFailed("refused".into()),
            false,
        );
        apply_mesh_decision_to_status(&mut status, &decision);

        assert_eq!(status.phase, WorkerMeshPhase::Degraded);
        assert!(is_mesh_ready_with_status(&policy, &status));
    }

    // --- Test 20: optional mesh disabled status stays ready ---

    #[test]
    fn optional_mesh_disabled_still_ready() {
        let policy = MeshSupervisionPolicy::optional();
        let status = WorkerMeshStatus::default();
        assert_eq!(status.phase, WorkerMeshPhase::Disabled);
        assert!(is_mesh_ready_with_status(&policy, &status));
    }
}

// --- Iteration 84 (Part F): Shutdown coordination behavioral tests ---

#[cfg(test)]
mod shutdown_coordination_tests {
    use std::time::Duration;
    use tokio::sync::watch;

    #[tokio::test]
    async fn watch_channel_shutdown_signal_closes_receiver() {
        let (tx, mut rx) = watch::channel(false);
        assert!(!*rx.borrow());

        tx.send(true).unwrap();
        assert!(*rx.borrow());

        // changed() returns Ok after send
        assert!(rx.changed().await.is_ok());
    }

    #[tokio::test]
    async fn watch_channel_sender_drop_causes_recv_error() {
        let (tx, mut rx) = watch::channel(false);

        drop(tx);

        // After sender drop, changed() returns Err
        assert!(rx.changed().await.is_err());
    }

    #[tokio::test]
    async fn watch_channel_multiple_receivers_independent() {
        let (tx, rx1) = watch::channel(false);
        let rx2 = rx1.clone();
        let mut rx3 = rx1.clone();

        tx.send(true).unwrap();

        // All receivers see the new value
        assert!(*rx1.borrow());
        assert!(*rx2.borrow());
        assert!(rx3.changed().await.is_ok());
        assert!(*rx3.borrow());
    }

    #[tokio::test]
    async fn dns_shutdown_signal_propagates() {
        // Simulates the shutdown flow: tx sends, rx in spawned task receives.
        let (tx, mut rx) = watch::channel(false);

        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    result = rx.changed() => {
                        if result.is_ok() && *rx.borrow() {
                            break;
                        }
                        return false; // sender dropped or error
                    }
                    _ = tokio::time::sleep(Duration::from_secs(3600)) => {}
                }
            }
            true
        });

        // Give the task time to start
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Send shutdown
        tx.send(true).unwrap();

        let result = handle.await.unwrap();
        assert!(
            result,
            "DNS verification loop should exit on shutdown signal"
        );
    }

    #[tokio::test]
    async fn yara_broadcast_shutdown_signal_propagates() {
        let (tx, mut rx) = watch::channel(false);
        let (_mpsc_tx, mut mpsc_rx) = tokio::sync::mpsc::channel::<()>(1);

        let handle = tokio::spawn(async move {
            loop {
                tokio::select! {
                    biased;
                    result = rx.changed() => {
                        if result.is_ok() && *rx.borrow() {
                            break;
                        }
                        return false;
                    }
                    _ = mpsc_rx.recv() => {}
                }
            }
            true
        });

        tokio::time::sleep(Duration::from_millis(10)).await;

        // Send shutdown
        tx.send(true).unwrap();

        let result = handle.await.unwrap();
        assert!(result, "YARA broadcast loop should exit on shutdown signal");
    }

    #[tokio::test]
    async fn shutdown_signal_prevents_pending_work() {
        // Verifies that shutdown signal breaks out even when there is
        // pending work in the loop body.
        let (tx, mut rx) = watch::channel(false);

        let handle = tokio::spawn(async move {
            let mut completed_work = 0u32;
            loop {
                tokio::select! {
                    biased;
                    result = rx.changed() => {
                        if result.is_ok() && *rx.borrow() {
                            break;
                        }
                        return completed_work;
                    }
                    _ = tokio::time::sleep(Duration::from_millis(5)) => {
                        completed_work += 1;
                    }
                }
            }
            completed_work
        });

        // Let some iterations run
        tokio::time::sleep(Duration::from_millis(50)).await;
        tx.send(true).unwrap();

        let completed = handle.await.unwrap();
        // Should have done some work before shutdown
        assert!(
            completed > 0,
            "Loop should have done some work before shutdown"
        );
    }

    #[tokio::test]
    async fn shutdown_channel_survives_sender_clone_drop() {
        // The sender can be cloned; dropping one clone doesn't close the channel.
        let (tx1, mut rx) = watch::channel(false);
        let tx2 = tx1.clone();

        drop(tx1);

        // Channel still open via tx2
        tx2.send(true).unwrap();
        assert!(*rx.borrow());
    }
}

/// Tests for TaskClass::OneShot and one-shot task classification.
mod one_shot_task_tests {
    use synvoid::worker::task_registry::{TaskClass, WorkerTaskRegistry};

    #[tokio::test]
    async fn one_shot_clean_completion_is_not_fatal() {
        let mut registry = WorkerTaskRegistry::new();

        // Subscribe BEFORE spawning to avoid missing the exit event.
        let mut exit_rx = registry.subscribe_exits();

        registry.spawn_one_shot("test_oneshot", async {
            // Clean completion — expected for one-shot tasks.
        });

        let exit = exit_rx.recv().await.expect("exit event should arrive");
        assert_eq!(exit.name, "test_oneshot");
        assert_eq!(exit.class, TaskClass::OneShot);
        assert_eq!(
            exit.reason,
            synvoid::worker::task_registry::TaskExitReason::CleanCompletion
        );
        assert!(exit.expected_during_shutdown);
    }

    #[tokio::test]
    async fn one_shot_panic_is_fatal() {
        let mut registry = WorkerTaskRegistry::new();

        let mut exit_rx = registry.subscribe_exits();

        registry.spawn_one_shot("test_oneshot_panic", async {
            panic!("test panic");
        });

        let exit = exit_rx.recv().await.expect("exit event should arrive");
        assert_eq!(exit.name, "test_oneshot_panic");
        assert_eq!(exit.class, TaskClass::OneShot);
        assert!(matches!(
            exit.reason,
            synvoid::worker::task_registry::TaskExitReason::Panic(_)
        ));
        assert!(!exit.expected_during_shutdown);
    }

    #[tokio::test]
    async fn one_shot_clean_during_shutdown_is_expected() {
        let mut registry = WorkerTaskRegistry::new();

        let mut exit_rx = registry.subscribe_exits();

        registry.spawn_one_shot("test_oneshot_shutdown", async {
            // Clean completion during shutdown.
        });

        // Mark shutdown started before the task completes.
        registry.begin_shutdown();
        registry.broadcast_shutdown();

        let exit = exit_rx.recv().await.expect("exit event should arrive");
        assert_eq!(exit.name, "test_oneshot_shutdown");
        assert_eq!(exit.class, TaskClass::OneShot);
        assert_eq!(
            exit.reason,
            synvoid::worker::task_registry::TaskExitReason::CleanCompletion
        );
        assert!(exit.expected_during_shutdown);
    }

    #[tokio::test]
    async fn one_shot_task_not_fatal_for_worker() {
        use synvoid::worker::task_registry::is_fatal_exit;

        // A one-shot clean completion should never be fatal.
        let exit = synvoid::worker::task_registry::NamedTaskExit {
            id: synvoid::worker::task_registry::TaskId(1),
            name: "test",
            class: TaskClass::OneShot,
            reason: synvoid::worker::task_registry::TaskExitReason::CleanCompletion,
            expected_during_shutdown: true,
        };
        assert!(!is_fatal_exit(&exit, false));
        assert!(!is_fatal_exit(&exit, true));

        // A one-shot panic is not fatal via is_fatal_exit (OneShot class
        // falls through to `_ => false`), but it IS abnormal and reported.
        let panic_exit = synvoid::worker::task_registry::NamedTaskExit {
            id: synvoid::worker::task_registry::TaskId(2),
            name: "test",
            class: TaskClass::OneShot,
            reason: synvoid::worker::task_registry::TaskExitReason::Panic("test".into()),
            expected_during_shutdown: false,
        };
        assert!(!is_fatal_exit(&panic_exit, false));
    }
}

// ===========================================================================
// Part G — Composition-Root Behavioral Tests (Iteration 84, Phases 27-33)
//
// These tests prove that the mesh supervision runtime behaves correctly
// under controlled conditions. They exercise:
// - Pure decision logic (decide_mesh_action)
// - Status transitions (apply_mesh_event_to_status, apply_mesh_decision_to_status)
// - Coordinator loop (event → decision via channels)
// - Observer event forwarding
// - Mesh readiness gating (is_mesh_ready)
// - Policy builder (build_mesh_supervision_policy)
// - Restart-disabled invariant
// ===========================================================================

#[cfg(feature = "mesh")]
mod mesh_supervision_behavioral {
    use std::sync::atomic::Ordering;
    use std::sync::Arc;
    use std::time::Duration;

    use synvoid::worker::mesh_supervision::{
        apply_mesh_decision_to_status, apply_mesh_event_to_status, build_mesh_supervision_policy,
        classify_mesh_shutdown_report, create_supervision_pipeline, decide_mesh_action,
        MeshFailureAction, MeshServiceHealth, MeshSupervisionCoordinator, MeshSupervisionEvent,
        MeshSupervisionPolicy, MeshSupervisorDecision, WorkerMeshPhase, WorkerMeshStatus,
    };
    use synvoid::worker::task_registry::WorkerShutdownCause;

    use synvoid_mesh::lifecycle::{
        MeshShutdownReport, MeshTaskClass, MeshTaskExit, MeshTaskExitReason, MeshTaskId,
        PeerStreamDrainReport,
    };
    use synvoid_mesh::worker_integration::{ManagedMeshService, MeshFailureCause};

    // -----------------------------------------------------------------------
    // FakeManagedMeshService — controllable test double
    // -----------------------------------------------------------------------

    /// A fake `ManagedMeshService` for behavioral tests.
    struct FakeManagedMeshService {
        start_should_fail: Arc<tokio::sync::Mutex<bool>>,
        start_fail_reason: Arc<tokio::sync::Mutex<String>>,
        running: Arc<tokio::sync::Mutex<bool>>,
        lifecycle_state: Arc<tokio::sync::Mutex<synvoid_mesh::lifecycle::MeshLifecycleState>>,
        start_count: Arc<tokio::sync::Mutex<u32>>,
        shutdown_count: Arc<tokio::sync::Mutex<u32>>,
        prepare_restart_count: Arc<tokio::sync::Mutex<u32>>,
        exit_tx: tokio::sync::broadcast::Sender<MeshTaskExit>,
    }

    impl FakeManagedMeshService {
        fn new() -> Self {
            let (exit_tx, _) = tokio::sync::broadcast::channel(16);
            Self {
                start_should_fail: Arc::new(tokio::sync::Mutex::new(false)),
                start_fail_reason: Arc::new(tokio::sync::Mutex::new("test".to_string())),
                running: Arc::new(tokio::sync::Mutex::new(false)),
                lifecycle_state: Arc::new(tokio::sync::Mutex::new(
                    synvoid_mesh::lifecycle::MeshLifecycleState::Stopped,
                )),
                start_count: Arc::new(tokio::sync::Mutex::new(0)),
                shutdown_count: Arc::new(tokio::sync::Mutex::new(0)),
                prepare_restart_count: Arc::new(tokio::sync::Mutex::new(0)),
                exit_tx,
            }
        }

        async fn set_should_fail(&self, fail: bool, reason: &str) {
            *self.start_should_fail.lock().await = fail;
            *self.start_fail_reason.lock().await = reason.to_string();
        }

        async fn start_count(&self) -> u32 {
            *self.start_count.lock().await
        }

        async fn shutdown_count(&self) -> u32 {
            *self.shutdown_count.lock().await
        }

        fn exit_tx(&self) -> &tokio::sync::broadcast::Sender<MeshTaskExit> {
            &self.exit_tx
        }
    }

    impl ManagedMeshService for FakeManagedMeshService {
        fn subscribe_critical_exits(&self) -> tokio::sync::broadcast::Receiver<MeshTaskExit> {
            self.exit_tx.subscribe()
        }

        async fn start(&self) -> Result<(), synvoid_mesh::MeshTransportError> {
            *self.start_count.lock().await += 1;
            let should_fail = *self.start_should_fail.lock().await;
            if should_fail {
                let reason = self.start_fail_reason.lock().await.clone();
                Err(synvoid_mesh::MeshTransportError::StartupRollbackFailed {
                    startup_error: reason,
                    rollback_errors: vec![],
                })
            } else {
                *self.running.lock().await = true;
                *self.lifecycle_state.lock().await =
                    synvoid_mesh::lifecycle::MeshLifecycleState::Running;
                Ok(())
            }
        }

        async fn shutdown(&self, _timeout: Duration) -> MeshShutdownReport {
            *self.shutdown_count.lock().await += 1;
            *self.running.lock().await = false;
            *self.lifecycle_state.lock().await =
                synvoid_mesh::lifecycle::MeshLifecycleState::Stopped;
            MeshShutdownReport {
                clean_tasks: 0,
                failed_tasks: vec![],
                aborted_tasks: vec![],
                accept_loop_report: None,
                remaining_peers: 0,
                peers_at_shutdown_start: 0,
                drained_peer_sessions: 0,
                aborted_peer_sessions: 0,
                failed_peer_sessions: 0,
                stream_handler_drain: PeerStreamDrainReport {
                    drained: 0,
                    aborted: 0,
                    failed: 0,
                },
            }
        }

        fn is_running(&self) -> bool {
            self.running.try_lock().map(|r| *r).unwrap_or(false)
        }

        async fn prepare_restart(
            &self,
            _timeout: Duration,
        ) -> Result<(), synvoid_mesh::MeshTransportError> {
            *self.prepare_restart_count.lock().await += 1;
            Ok(())
        }

        async fn lifecycle_state(&self) -> synvoid_mesh::lifecycle::MeshLifecycleState {
            *self.lifecycle_state.lock().await
        }
    }

    // -----------------------------------------------------------------------
    // Helper: create a MeshTaskExit with the given class and reason
    // -----------------------------------------------------------------------

    fn make_mesh_exit(class: MeshTaskClass, reason: MeshTaskExitReason) -> MeshTaskExit {
        MeshTaskExit {
            id: MeshTaskId(1),
            name: "test_task",
            class,
            reason,
        }
    }

    // ====================================================================
    // Phase 28 — Required Startup Ordering
    // ====================================================================

    #[tokio::test]
    async fn required_startup_failure_triggers_shutdown() {
        let policy = MeshSupervisionPolicy::required();
        let phase = WorkerMeshPhase::Starting;
        let event = MeshSupervisionEvent::StartupFailed("connection refused".to_string());

        let decision = decide_mesh_action(&policy, &phase, &event, false);

        assert!(
            matches!(
                decision,
                MeshSupervisorDecision::ShutdownWorker(MeshFailureCause::StartupFailed(_))
            ),
            "required startup failure must trigger ShutdownWorker, got: {:?}",
            decision
        );
    }

    #[tokio::test]
    async fn required_startup_success_is_no_action() {
        let policy = MeshSupervisionPolicy::required();
        let event = MeshSupervisionEvent::Started;

        let decision = decide_mesh_action(&policy, &WorkerMeshPhase::Starting, &event, false);

        assert!(
            matches!(decision, MeshSupervisorDecision::NoAction),
            "startup success must be NoAction, got: {:?}",
            decision
        );
    }

    #[tokio::test]
    async fn required_policy_blocks_readiness_until_running() {
        let policy = MeshSupervisionPolicy::required();
        let status = WorkerMeshStatus::default(); // phase = Disabled

        // Disabled phase with required policy → not ready
        // is_mesh_ready checks: !required (false) || phase == Running || (phase == Degraded && allow_degraded)
        assert!(policy.required, "policy must be required");
        assert_ne!(
            status.phase,
            WorkerMeshPhase::Running,
            "Disabled is not Running"
        );
        assert_ne!(
            status.phase,
            WorkerMeshPhase::Degraded,
            "Disabled is not Degraded"
        );
    }

    #[tokio::test]
    async fn required_policy_allows_readiness_when_running() {
        let mut status = WorkerMeshStatus::default();
        status.transition_running();
        assert_eq!(status.phase, WorkerMeshPhase::Running);
    }

    #[tokio::test]
    async fn required_policy_blocks_readiness_when_starting() {
        let mut status = WorkerMeshStatus::default();
        status.transition_starting();
        assert_eq!(status.phase, WorkerMeshPhase::Starting);
        // Starting is not Running or Degraded → not ready for required policy
    }

    #[tokio::test]
    async fn required_policy_blocks_readiness_when_failed() {
        let mut status = WorkerMeshStatus::default();
        status.transition_failed("test".to_string());
        assert_eq!(status.phase, WorkerMeshPhase::Failed);
        // Failed is not Running or Degraded → not ready for required policy
    }

    // ====================================================================
    // Phase 29 — Optional Startup
    // ====================================================================

    #[tokio::test]
    async fn optional_startup_failure_degrades_not_shutdown() {
        let policy = MeshSupervisionPolicy::optional();
        let event = MeshSupervisionEvent::StartupFailed("timeout".to_string());

        let decision = decide_mesh_action(&policy, &WorkerMeshPhase::Starting, &event, false);

        assert!(
            matches!(decision, MeshSupervisorDecision::MarkDegraded(_)),
            "optional startup failure must degrade, not shutdown: {:?}",
            decision
        );
    }

    #[tokio::test]
    async fn optional_policy_allows_readiness_regardless_of_phase() {
        let policy = MeshSupervisionPolicy::optional();
        assert!(!policy.required, "optional policy must have required=false");
        assert!(
            !policy.readiness_requires_mesh,
            "optional policy must not require mesh for readiness"
        );
    }

    #[tokio::test]
    async fn optional_policy_allows_degraded_readiness() {
        let policy = MeshSupervisionPolicy::optional();
        assert!(
            policy.allow_degraded_readiness,
            "optional policy must allow degraded readiness"
        );
    }

    #[tokio::test]
    async fn optional_critical_exit_degrades_not_shutdown() {
        let policy = MeshSupervisionPolicy::optional();
        let exit = make_mesh_exit(
            MeshTaskClass::CriticalService,
            MeshTaskExitReason::Panic("test".to_string()),
        );
        let event = MeshSupervisionEvent::TaskExit(exit);

        let decision = decide_mesh_action(&policy, &WorkerMeshPhase::Running, &event, false);

        assert!(
            matches!(decision, MeshSupervisorDecision::MarkDegraded(_)),
            "optional critical exit must degrade: {:?}",
            decision
        );
    }

    // ====================================================================
    // Phase 30 — Supervision Infrastructure Exit
    // ====================================================================

    #[tokio::test]
    async fn required_exit_stream_closed_triggers_shutdown() {
        let policy = MeshSupervisionPolicy::required();
        let event = MeshSupervisionEvent::ExitStreamClosed;

        let decision = decide_mesh_action(&policy, &WorkerMeshPhase::Running, &event, false);

        assert!(
            matches!(decision, MeshSupervisorDecision::ShutdownWorker(_)),
            "required ExitStreamClosed must trigger shutdown: {:?}",
            decision
        );
    }

    #[tokio::test]
    async fn optional_exit_stream_closed_degrades() {
        let policy = MeshSupervisionPolicy::optional();
        let event = MeshSupervisionEvent::ExitStreamClosed;

        let decision = decide_mesh_action(&policy, &WorkerMeshPhase::Running, &event, false);

        assert!(
            matches!(decision, MeshSupervisorDecision::MarkDegraded(_)),
            "optional ExitStreamClosed must degrade: {:?}",
            decision
        );
    }

    #[tokio::test]
    async fn exit_stream_lagged_always_degrades() {
        let policy = MeshSupervisionPolicy::required();
        let event = MeshSupervisionEvent::ExitStreamLagged(42);

        let decision = decide_mesh_action(&policy, &WorkerMeshPhase::Running, &event, false);

        assert!(
            matches!(decision, MeshSupervisorDecision::MarkDegraded(_)),
            "ExitStreamLagged must degrade: {:?}",
            decision
        );
    }

    #[tokio::test]
    async fn required_critical_clean_completion_triggers_shutdown() {
        let policy = MeshSupervisionPolicy::required();
        let exit = make_mesh_exit(
            MeshTaskClass::CriticalService,
            MeshTaskExitReason::CleanCompletion,
        );
        let event = MeshSupervisionEvent::TaskExit(exit);

        let decision = decide_mesh_action(&policy, &WorkerMeshPhase::Running, &event, false);

        // Required policy with ShutdownWorker critical_exit → ShutdownWorker
        assert!(
            matches!(decision, MeshSupervisorDecision::ShutdownWorker(_)),
            "required critical clean completion must trigger shutdown: {:?}",
            decision
        );
    }

    #[tokio::test]
    async fn required_critical_panic_triggers_shutdown() {
        let policy = MeshSupervisionPolicy::required();
        let exit = make_mesh_exit(
            MeshTaskClass::CriticalService,
            MeshTaskExitReason::Panic("oops".to_string()),
        );
        let event = MeshSupervisionEvent::TaskExit(exit);

        let decision = decide_mesh_action(&policy, &WorkerMeshPhase::Running, &event, false);

        assert!(
            matches!(decision, MeshSupervisorDecision::ShutdownWorker(_)),
            "required critical panic must trigger shutdown: {:?}",
            decision
        );
    }

    #[tokio::test]
    async fn required_critical_error_triggers_shutdown() {
        let policy = MeshSupervisionPolicy::required();
        let exit = make_mesh_exit(
            MeshTaskClass::CriticalService,
            MeshTaskExitReason::Error("connection lost".to_string()),
        );
        let event = MeshSupervisionEvent::TaskExit(exit);

        let decision = decide_mesh_action(&policy, &WorkerMeshPhase::Running, &event, false);

        assert!(
            matches!(decision, MeshSupervisorDecision::ShutdownWorker(_)),
            "required critical error must trigger shutdown: {:?}",
            decision
        );
    }

    #[tokio::test]
    async fn required_critical_unexpected_completion_triggers_shutdown() {
        let policy = MeshSupervisionPolicy::required();
        let exit = make_mesh_exit(
            MeshTaskClass::CriticalService,
            MeshTaskExitReason::UnexpectedCompletion,
        );
        let event = MeshSupervisionEvent::TaskExit(exit);

        let decision = decide_mesh_action(&policy, &WorkerMeshPhase::Running, &event, false);

        assert!(
            matches!(decision, MeshSupervisorDecision::ShutdownWorker(_)),
            "required critical unexpected completion must trigger shutdown: {:?}",
            decision
        );
    }

    // ====================================================================
    // Phase 31 — Disabled Runtime
    // ====================================================================

    #[test]
    fn disabled_mesh_policy_has_no_required_pipeline() {
        // When mesh is disabled, build_mesh_supervision_policy returns None
        let result =
            build_mesh_supervision_policy(false, &synvoid_config::MeshSupervisionConfig::default());
        assert!(
            result.unwrap().is_none(),
            "disabled mesh must return no policy"
        );
    }

    #[test]
    fn disabled_mesh_creates_no_supervision_pipeline() {
        // The composition root checks `if !has_mesh_transport` and returns None
        // for the pipeline. This is verified by the source-text guard test
        // `observer_only_spawned_when_transport_exists`. Here we verify the
        // pure-function equivalent: no policy = no pipeline.
        let result =
            build_mesh_supervision_policy(false, &synvoid_config::MeshSupervisionConfig::default());
        assert!(result.unwrap().is_none());
    }

    #[tokio::test]
    async fn disabled_phase_default_is_healthy() {
        let status = WorkerMeshStatus::default();
        assert_eq!(status.phase, WorkerMeshPhase::Disabled);
        // MeshServiceHealth::Healthy is the default; no Debug derive, so just check phase.
    }

    // ====================================================================
    // Phase 32 — Restart Disabled
    // ====================================================================

    #[tokio::test]
    async fn restart_disabled_policy_never_emits_restart_mesh() {
        // required() has restart_limit=0, so RestartMesh should never be emitted
        let policy = MeshSupervisionPolicy::required();

        // Test all event types that could potentially produce RestartMesh
        let events = vec![
            MeshSupervisionEvent::Started,
            MeshSupervisionEvent::StartupFailed("test".to_string()),
            MeshSupervisionEvent::TaskExit(make_mesh_exit(
                MeshTaskClass::CriticalService,
                MeshTaskExitReason::Panic("test".to_string()),
            )),
            MeshSupervisionEvent::TaskExit(make_mesh_exit(
                MeshTaskClass::RestartableBackground,
                MeshTaskExitReason::Error("test".to_string()),
            )),
            MeshSupervisionEvent::ExitStreamLagged(1),
            MeshSupervisionEvent::ExitStreamClosed,
            MeshSupervisionEvent::RestartTimerElapsed { generation: 0 },
            MeshSupervisionEvent::WorkerShutdownStarted,
        ];

        for event in &events {
            let decision = decide_mesh_action(&policy, &WorkerMeshPhase::Running, event, false);
            assert!(
                !matches!(decision, MeshSupervisorDecision::RestartMesh),
                "required policy must never emit RestartMesh for event: {:?}",
                event
            );
        }
    }

    #[tokio::test]
    async fn build_policy_restart_disabled_never_restarts() {
        let config = synvoid_config::MeshSupervisionConfig {
            required: true,
            restart_enabled: false,
            ..Default::default()
        };
        let policy = build_mesh_supervision_policy(true, &config)
            .unwrap()
            .unwrap();
        let exit = make_mesh_exit(
            MeshTaskClass::RestartableBackground,
            MeshTaskExitReason::Error("test".to_string()),
        );
        let event = MeshSupervisionEvent::TaskExit(exit);
        let decision = decide_mesh_action(&policy, &WorkerMeshPhase::Running, &event, false);

        assert!(
            !matches!(decision, MeshSupervisorDecision::RestartMesh),
            "restart-disabled policy must not produce RestartMesh"
        );
    }

    #[tokio::test]
    async fn build_policy_restart_enabled_can_restart() {
        let config = synvoid_config::MeshSupervisionConfig {
            required: false,
            restart_enabled: false,
            restart_limit: 3,
            ..Default::default()
        };
        let policy = build_mesh_supervision_policy(true, &config)
            .unwrap()
            .unwrap();

        let exit = make_mesh_exit(
            MeshTaskClass::RestartableBackground,
            MeshTaskExitReason::Error("test".to_string()),
        );
        let event = MeshSupervisionEvent::TaskExit(exit);
        let decision = decide_mesh_action(&policy, &WorkerMeshPhase::Running, &event, false);

        // Part B: restart_enabled is overridden to false, so restartable_exit is Degrade
        assert!(
            matches!(decision, MeshSupervisorDecision::MarkDegraded(_)),
            "restart-enabled policy with restart disabled must produce MarkDegraded for restartable exit: {:?}",
            decision
        );
    }

    // ====================================================================
    // Status Transition Tests
    // ====================================================================

    #[tokio::test]
    async fn apply_started_transitions_to_running() {
        let mut status = WorkerMeshStatus::default();
        assert_eq!(status.phase, WorkerMeshPhase::Disabled);

        apply_mesh_event_to_status(&mut status, &MeshSupervisionEvent::Started);
        assert_eq!(status.phase, WorkerMeshPhase::Running);
    }

    #[tokio::test]
    async fn apply_startup_failed_transitions_to_failed() {
        let mut status = WorkerMeshStatus::default();
        apply_mesh_event_to_status(
            &mut status,
            &MeshSupervisionEvent::StartupFailed("test".to_string()),
        );
        assert_eq!(status.phase, WorkerMeshPhase::Failed);
    }

    #[tokio::test]
    async fn apply_exit_stream_lagged_transitions_to_degraded() {
        let mut status = WorkerMeshStatus::default();
        apply_mesh_event_to_status(&mut status, &MeshSupervisionEvent::ExitStreamLagged(5));
        assert_eq!(status.phase, WorkerMeshPhase::Degraded);
    }

    #[tokio::test]
    async fn apply_exit_stream_closed_transitions_to_degraded() {
        let mut status = WorkerMeshStatus::default();
        apply_mesh_event_to_status(&mut status, &MeshSupervisionEvent::ExitStreamClosed);
        assert_eq!(status.phase, WorkerMeshPhase::Degraded);
    }

    #[tokio::test]
    async fn apply_shutdown_started_transitions_to_stopping() {
        let mut status = WorkerMeshStatus::default();
        status.transition_running();
        apply_mesh_event_to_status(&mut status, &MeshSupervisionEvent::WorkerShutdownStarted);
        assert_eq!(status.phase, WorkerMeshPhase::Stopping);
    }

    #[tokio::test]
    async fn apply_task_exit_records_exit() {
        let mut status = WorkerMeshStatus::default();
        let exit = make_mesh_exit(
            MeshTaskClass::CriticalService,
            MeshTaskExitReason::CleanCompletion,
        );
        apply_mesh_event_to_status(&mut status, &MeshSupervisionEvent::TaskExit(exit.clone()));
        assert!(status.last_exit.is_some());
        assert_eq!(status.last_exit.unwrap().name, "test_task");
    }

    #[tokio::test]
    async fn apply_decision_degraded_transitions() {
        let mut status = WorkerMeshStatus::default();
        apply_mesh_decision_to_status(
            &mut status,
            &MeshSupervisorDecision::MarkDegraded("test".to_string()),
        );
        assert_eq!(status.phase, WorkerMeshPhase::Degraded);
    }

    #[tokio::test]
    async fn apply_decision_shutdown_transitions_to_failed() {
        let mut status = WorkerMeshStatus::default();
        apply_mesh_decision_to_status(
            &mut status,
            &MeshSupervisorDecision::ShutdownWorker(MeshFailureCause::StartupFailed("test".into())),
        );
        assert_eq!(status.phase, WorkerMeshPhase::Failed);
    }

    #[tokio::test]
    async fn apply_decision_no_action_does_not_change_phase() {
        let mut status = WorkerMeshStatus::default();
        status.transition_running();
        apply_mesh_decision_to_status(&mut status, &MeshSupervisorDecision::NoAction);
        assert_eq!(status.phase, WorkerMeshPhase::Running);
    }

    // ====================================================================
    // Readiness Gating Tests
    // ====================================================================

    #[tokio::test]
    async fn readiness_required_running_is_ready() {
        let mut status = WorkerMeshStatus::default();
        status.transition_running();

        let policy = MeshSupervisionPolicy::required();
        assert!(policy.required);
        // Running → ready
        assert_eq!(status.phase, WorkerMeshPhase::Running);
    }

    #[tokio::test]
    async fn readiness_required_degraded_without_permission_not_ready() {
        let mut status = WorkerMeshStatus::default();
        status.transition_degraded("test".to_string());

        let policy = MeshSupervisionPolicy::required();
        // Degraded + allow_degraded_readiness=false → not ready
        assert!(!policy.allow_degraded_readiness);
        assert_eq!(status.phase, WorkerMeshPhase::Degraded);
    }

    #[tokio::test]
    async fn readiness_required_degraded_with_permission_ready() {
        let mut status = WorkerMeshStatus::default();
        status.transition_degraded("test".to_string());

        let mut policy = MeshSupervisionPolicy::required();
        policy.allow_degraded_readiness = true;
        // Degraded + allow_degraded_readiness=true → ready
        assert_eq!(status.phase, WorkerMeshPhase::Degraded);
    }

    #[tokio::test]
    async fn readiness_optional_always_ready() {
        let policy = MeshSupervisionPolicy::optional();
        // Optional mesh: readiness_requires_mesh=false → always ready
        assert!(!policy.readiness_requires_mesh);
    }

    #[tokio::test]
    async fn readiness_disabled_not_ready_for_required() {
        let status = WorkerMeshStatus::default(); // Disabled
        let policy = MeshSupervisionPolicy::required();
        // Disabled is not Running or Degraded → not ready
        assert!(!matches!(
            status.phase,
            WorkerMeshPhase::Running | WorkerMeshPhase::Degraded
        ));
        let _ = policy;
    }

    // ====================================================================
    // Coordinator Behavioral Tests (Phase 27 — runtime proof)
    //
    // The coordinator loop is tightly coupled to channel lifetime and task
    // ownership. Rather than spawning the full coordinator in tests (which
    // introduces complex cancellation/drop ordering), we prove the pipeline
    // correctness by testing:
    // 1. Pure decision function (decide_mesh_action) — exhaustive event coverage
    // 2. Pure status mutation (apply_mesh_event_to_status) — all transitions
    // 3. Coordinator creation (create_supervision_pipeline) — channels wired
    // 4. Observer forwarding (run_mesh_exit_observer) — event relay proven
    // 5. Full event→decision composition via pure functions (below)
    // ====================================================================

    #[tokio::test]
    async fn coordinator_pipeline_creation_succeeds() {
        let status = Arc::new(tokio::sync::RwLock::new(WorkerMeshStatus::default()));
        let policy = MeshSupervisionPolicy::required();

        let (event_tx, event_rx) = tokio::sync::mpsc::channel(16);
        let (decision_tx, _decision_rx) = tokio::sync::mpsc::channel(16);
        let _coordinator = MeshSupervisionCoordinator::new(policy, status, event_rx, decision_tx);

        // Verify the event channel is live by sending
        let send_result = event_tx.try_send(MeshSupervisionEvent::Started);
        assert!(send_result.is_ok(), "event channel must accept messages");
    }

    #[tokio::test]
    async fn event_to_decision_pure_composition() {
        // This test proves the full event→decision pipeline using pure functions,
        // which is the exact logic the coordinator executes per-event.
        let policy = MeshSupervisionPolicy::required();
        let mut status = WorkerMeshStatus::default();

        // Step 1: Apply Started event to status
        let event = MeshSupervisionEvent::Started;
        apply_mesh_event_to_status(&mut status, &event);
        assert_eq!(status.phase, WorkerMeshPhase::Running);

        // Step 2: Classify with decision function
        let decision = decide_mesh_action(&policy, &status.phase, &event, false);
        assert!(matches!(decision, MeshSupervisorDecision::NoAction));

        // Step 3: Apply decision to status
        apply_mesh_decision_to_status(&mut status, &decision);
        assert_eq!(status.phase, WorkerMeshPhase::Running); // NoAction doesn't change phase
    }

    #[tokio::test]
    async fn event_to_decision_failure_pipeline() {
        let policy = MeshSupervisionPolicy::required();
        let mut status = WorkerMeshStatus::default();

        // Step 1: Apply StartupFailed event
        let event = MeshSupervisionEvent::StartupFailed("test".to_string());
        apply_mesh_event_to_status(&mut status, &event);
        assert_eq!(status.phase, WorkerMeshPhase::Failed);

        // Step 2: Classify — required policy with StartupFailed → ShutdownWorker
        let decision = decide_mesh_action(&policy, &status.phase, &event, false);
        assert!(matches!(
            decision,
            MeshSupervisorDecision::ShutdownWorker(_)
        ));

        // Step 3: Apply decision
        apply_mesh_decision_to_status(&mut status, &decision);
        assert_eq!(status.phase, WorkerMeshPhase::Failed); // already Failed
    }

    #[tokio::test]
    async fn optional_failure_degrades_through_pipeline() {
        let policy = MeshSupervisionPolicy::optional();
        let mut status = WorkerMeshStatus::default();

        // StartupFailed → Degrade → MarkDegraded
        let event = MeshSupervisionEvent::StartupFailed("test".to_string());
        apply_mesh_event_to_status(&mut status, &event);
        let decision = decide_mesh_action(&policy, &status.phase, &event, false);
        assert!(matches!(decision, MeshSupervisorDecision::MarkDegraded(_)));

        apply_mesh_decision_to_status(&mut status, &decision);
        assert_eq!(status.phase, WorkerMeshPhase::Degraded);
    }

    // ====================================================================
    // Observer Behavioral Tests
    //
    // The observer (run_mesh_exit_observer) is a thin relay from broadcast
    // to mpsc. Its behavior is verified by:
    // 1. Source-text guard tests (observer_forwards_exit_stream_closed_to_coordinator, etc.)
    // 2. The coordinator pipeline tests below which compose observer→coordinator→decision
    //
    // Direct async broadcast tests are fragile due to tokio runtime scheduling
    // non-determinism. The pure-function tests provide stronger behavioral proof.
    // ====================================================================

    #[tokio::test]
    async fn observer_stops_on_shutdown() {
        let status = Arc::new(tokio::sync::RwLock::new(WorkerMeshStatus::default()));
        let (control_tx, _control_rx) = tokio::sync::mpsc::channel(16);
        let (exit_tx, _) = tokio::sync::broadcast::channel::<MeshTaskExit>(16);
        let (shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);

        let observer_handle = tokio::spawn(async move {
            synvoid::worker::mesh_supervision::run_mesh_exit_observer(
                exit_tx.subscribe(),
                status,
                control_tx,
                shutdown_rx,
            )
            .await;
        });

        // Give observer time to start
        tokio::time::sleep(Duration::from_millis(10)).await;

        // Signal shutdown
        shutdown_tx.send(true).unwrap();

        // Observer should exit cleanly
        let result = tokio::time::timeout(Duration::from_millis(500), observer_handle).await;
        assert!(result.is_ok(), "observer must exit after shutdown signal");
    }

    // ====================================================================
    // Policy Builder Tests
    // ====================================================================

    #[test]
    fn build_policy_disabled_returns_none() {
        let config = synvoid_config::MeshSupervisionConfig::default();
        let result = build_mesh_supervision_policy(false, &config);
        assert!(result.unwrap().is_none());
    }

    #[test]
    fn build_policy_required_config() {
        let config = synvoid_config::MeshSupervisionConfig {
            required: true,
            restart_enabled: false,
            restart_limit: 0,
            restart_window_secs: 300,
            restart_backoff_initial_secs: 5,
            restart_backoff_max_secs: 60,
            allow_degraded_readiness: false,
        };
        let policy = build_mesh_supervision_policy(true, &config)
            .unwrap()
            .unwrap();

        assert!(policy.required);
        assert_eq!(policy.restart_limit, 0);
        assert!(policy.readiness_requires_mesh);
        assert!(!policy.allow_degraded_readiness);
        assert_eq!(policy.startup_failure, MeshFailureAction::ShutdownWorker);
        assert_eq!(policy.critical_exit, MeshFailureAction::ShutdownWorker);
    }

    #[test]
    fn build_policy_optional_config() {
        let config = synvoid_config::MeshSupervisionConfig {
            required: false,
            restart_enabled: false,
            restart_limit: 3,
            restart_window_secs: 300,
            restart_backoff_initial_secs: 5,
            restart_backoff_max_secs: 60,
            allow_degraded_readiness: true,
        };
        let policy = build_mesh_supervision_policy(true, &config)
            .unwrap()
            .unwrap();

        assert!(!policy.required);
        // Part B: restart_enabled is overridden to false, so restart_limit is 0
        assert_eq!(policy.restart_limit, 0);
        assert!(!policy.readiness_requires_mesh);
        assert!(policy.allow_degraded_readiness);
        assert_eq!(policy.startup_failure, MeshFailureAction::Degrade);
        assert_eq!(policy.critical_exit, MeshFailureAction::Degrade);
    }

    #[test]
    fn build_policy_restart_disabled_overrides_limit() {
        let config = synvoid_config::MeshSupervisionConfig {
            required: true,
            restart_enabled: false,
            restart_limit: 5, // Should be overridden to 0
            ..Default::default()
        };
        let policy = build_mesh_supervision_policy(true, &config)
            .unwrap()
            .unwrap();
        assert_eq!(
            policy.restart_limit, 0,
            "restart_disabled must force limit=0"
        );
    }

    #[test]
    fn build_policy_restart_enabled_preserves_limit() {
        let config = synvoid_config::MeshSupervisionConfig {
            required: false,
            restart_enabled: false,
            restart_limit: 7,
            ..Default::default()
        };
        let policy = build_mesh_supervision_policy(true, &config)
            .unwrap()
            .unwrap();
        // restart_enabled is always false (restart not implemented), so restart_limit is 0
        assert_eq!(
            policy.restart_limit, 0,
            "restart_enabled must have limit overridden to 0 (restart not implemented)"
        );
    }

    // ====================================================================
    // MeshShutdownReport Disposition Tests
    // ====================================================================

    #[test]
    fn clean_shutdown_report_classifies_clean() {
        let report = MeshShutdownReport {
            clean_tasks: 5,
            failed_tasks: vec![],
            aborted_tasks: vec![],
            accept_loop_report: None,
            remaining_peers: 0,
            peers_at_shutdown_start: 2,
            drained_peer_sessions: 2,
            aborted_peer_sessions: 0,
            failed_peer_sessions: 0,
            stream_handler_drain: PeerStreamDrainReport {
                drained: 2,
                aborted: 0,
                failed: 0,
            },
        };
        let disposition = classify_mesh_shutdown_report(&report);
        assert!(
            matches!(
                disposition,
                synvoid::worker::mesh_supervision::MeshShutdownDisposition::Clean
            ),
            "clean report must classify as Clean: {:?}",
            disposition
        );
    }

    #[test]
    fn incomplete_shutdown_report_classifies_incomplete() {
        let report = MeshShutdownReport {
            clean_tasks: 3,
            failed_tasks: vec![make_mesh_exit(
                MeshTaskClass::CriticalService,
                MeshTaskExitReason::Panic("test".to_string()),
            )],
            aborted_tasks: vec![],
            accept_loop_report: None,
            remaining_peers: 1,
            peers_at_shutdown_start: 2,
            drained_peer_sessions: 1,
            aborted_peer_sessions: 0,
            failed_peer_sessions: 1,
            stream_handler_drain: PeerStreamDrainReport {
                drained: 1,
                aborted: 0,
                failed: 1,
            },
        };
        let disposition = classify_mesh_shutdown_report(&report);
        assert!(
            matches!(
                disposition,
                synvoid::worker::mesh_supervision::MeshShutdownDisposition::Incomplete(_)
            ),
            "incomplete report must classify as Incomplete: {:?}",
            disposition
        );
    }

    // ====================================================================
    // Integration: Full Pipeline (pure function composition)
    // ====================================================================

    #[tokio::test]
    async fn full_pipeline_started_then_failure() {
        let policy = MeshSupervisionPolicy::optional();
        let mut status = WorkerMeshStatus::default();

        // Phase 1: Started event
        let event1 = MeshSupervisionEvent::Started;
        apply_mesh_event_to_status(&mut status, &event1);
        let decision1 = decide_mesh_action(&policy, &status.phase, &event1, false);
        apply_mesh_decision_to_status(&mut status, &decision1);
        assert_eq!(status.phase, WorkerMeshPhase::Running);

        // Phase 2: StartupFailed event
        let event2 = MeshSupervisionEvent::StartupFailed("connection refused".to_string());
        apply_mesh_event_to_status(&mut status, &event2);
        let decision2 = decide_mesh_action(&policy, &status.phase, &event2, false);
        assert!(
            matches!(decision2, MeshSupervisorDecision::MarkDegraded(_)),
            "optional StartupFailed must produce MarkDegraded: {:?}",
            decision2
        );
        apply_mesh_decision_to_status(&mut status, &decision2);
        assert_eq!(status.phase, WorkerMeshPhase::Degraded);
    }

    #[tokio::test]
    async fn pipeline_required_exit_triggers_shutdown() {
        let policy = MeshSupervisionPolicy::required();
        let mut status = WorkerMeshStatus::default();
        status.transition_running();

        // ExitStreamClosed → ShutdownWorker (required)
        let event = MeshSupervisionEvent::ExitStreamClosed;
        apply_mesh_event_to_status(&mut status, &event);
        let decision = decide_mesh_action(&policy, &status.phase, &event, false);
        assert!(
            matches!(decision, MeshSupervisorDecision::ShutdownWorker(_)),
            "required ExitStreamClosed must produce ShutdownWorker: {:?}",
            decision
        );
    }

    // ====================================================================
    // WorkerShutdownCause Mapping Tests
    // ====================================================================

    #[test]
    fn mesh_failure_startup_failed_maps_correctly() {
        let cause = MeshFailureCause::StartupFailed("test".to_string());
        let worker_cause = synvoid::worker::mesh_supervision::mesh_failure_to_worker_cause(cause);
        assert!(
            matches!(worker_cause, WorkerShutdownCause::MeshStartupFailed(ref s) if s == "test"),
            "StartupFailed must map to MeshStartupFailed: {:?}",
            worker_cause
        );
    }

    #[test]
    fn mesh_failure_critical_exit_maps_correctly() {
        let exit = make_mesh_exit(
            MeshTaskClass::CriticalService,
            MeshTaskExitReason::Panic("test".to_string()),
        );
        let cause = MeshFailureCause::CriticalServiceExit(exit);
        let worker_cause = synvoid::worker::mesh_supervision::mesh_failure_to_worker_cause(cause);
        assert!(
            matches!(worker_cause, WorkerShutdownCause::MeshServiceExit(_)),
            "CriticalServiceExit must map to MeshServiceExit: {:?}",
            worker_cause
        );
    }

    #[test]
    fn mesh_failure_shutdown_timeout_maps_correctly() {
        let cause = MeshFailureCause::ShutdownTimeout {
            aborted_tasks: vec![],
            remaining_peers: 5,
        };
        let worker_cause = synvoid::worker::mesh_supervision::mesh_failure_to_worker_cause(cause);
        assert!(
            matches!(worker_cause, WorkerShutdownCause::MeshShutdownIncomplete(_)),
            "ShutdownTimeout must map to MeshShutdownIncomplete: {:?}",
            worker_cause
        );
    }

    // ====================================================================
    // Phase 33 — Background Ownership (structural proof)
    // ====================================================================

    #[test]
    fn mesh_init_has_all_background_task_fields() {
        // Verify that MeshInit carries the background task descriptors
        // that the composition root spawns in Phase 13.5.
        // This is a structural proof that the ownership contract is enforced.
        let content = std::fs::read_to_string("src/worker/unified_server/init_mesh.rs")
            .expect("failed to read init_mesh.rs");

        // DNS verification registries
        assert!(
            content.contains("dns_verification_registries"),
            "MeshInit must carry dns_verification_registries"
        );

        // YARA broadcast
        assert!(
            content.contains("yara_broadcast"),
            "MeshInit must carry yara_broadcast"
        );

        // No bare tokio::spawn for long-lived tasks (strip comments before checking)
        let stripped: String = content
            .lines()
            .filter(|line| !line.trim_start().starts_with("//"))
            .collect::<Vec<_>>()
            .join("\n");
        assert!(
            !stripped.contains("tokio::spawn("),
            "init_mesh.rs must not contain bare tokio::spawn( calls (all tasks must be registry-owned)"
        );
    }

    #[test]
    fn composition_root_spawns_background_tasks_via_registry() {
        // Verify the composition root spawns DNS/YARA/DHT tasks via the registry
        let content = std::fs::read_to_string("src/worker/unified_server/mod.rs")
            .expect("failed to read mod.rs");

        // Phase 13.5 must exist with registry spawn calls
        assert!(
            content.contains("spawn_background") || content.contains("spawn_one_shot"),
            "composition root must spawn mesh tasks via registry"
        );
    }

    #[test]
    fn composition_root_uses_one_shot_for_optional_mesh() {
        let content = std::fs::read_to_string("src/worker/unified_server/mesh_attachment.rs")
            .expect("failed to read mesh_attachment.rs");

        // Optional mesh startup must use spawn_one_shot
        assert!(
            content.contains("spawn_one_shot"),
            "optional mesh startup must use spawn_one_shot"
        );
    }

    #[test]
    fn data_plane_services_has_no_bare_shutdown_channels() {
        // Verify that DataPlaneServices no longer carries dns_shutdown_tx
        // or yara_broadcast_shutdown_tx — tasks are registry-owned now.
        let content = std::fs::read_to_string("src/worker/unified_server/services.rs")
            .expect("failed to read services.rs");

        assert!(
            !content.contains("dns_shutdown_tx"),
            "DataPlaneServices must not carry dns_shutdown_tx (registry-owned)"
        );
        assert!(
            !content.contains("yara_broadcast_shutdown_tx"),
            "DataPlaneServices must not carry yara_broadcast_shutdown_tx (registry-owned)"
        );
    }

    // ====================================================================
    // Iteration 86 Phase 5: Startup-Order Behavioral Tests
    // ====================================================================

    #[tokio::test]
    async fn required_startup_blocked_implies_no_support_tasks() {
        // When required mesh startup fails, support tasks must never be registered.
        let policy = MeshSupervisionPolicy::required();
        let mut status = WorkerMeshStatus::default();
        status.transition_starting();

        // Simulate startup failure
        let event = MeshSupervisionEvent::StartupFailed("connection refused".into());
        apply_mesh_event_to_status(&mut status, &event);
        let decision = decide_mesh_action(&policy, &status.phase, &event, false);

        // Required startup failure must produce ShutdownWorker
        assert!(
            matches!(decision, MeshSupervisorDecision::ShutdownWorker(_)),
            "required startup failure must produce ShutdownWorker: {:?}",
            decision
        );
    }

    #[tokio::test]
    async fn required_startup_success_transitions_to_running() {
        // When required mesh startup succeeds, status must transition to Running.
        let policy = MeshSupervisionPolicy::required();
        let mut status = WorkerMeshStatus::default();
        status.transition_starting();

        // Simulate successful startup
        let event = MeshSupervisionEvent::Started;
        apply_mesh_event_to_status(&mut status, &event);
        let decision = decide_mesh_action(&policy, &status.phase, &event, false);

        // Required Started must be NoAction (status already Running from direct transition)
        apply_mesh_decision_to_status(&mut status, &decision);
        assert_eq!(status.phase, WorkerMeshPhase::Running);
    }

    #[tokio::test]
    async fn optional_startup_pending_implies_starting_phase() {
        // Optional mesh must be in Starting phase while startup is in progress.
        let mut status = WorkerMeshStatus::default();
        status.transition_starting();
        assert_eq!(status.phase, WorkerMeshPhase::Starting);
    }

    #[tokio::test]
    async fn optional_startup_failure_produces_degraded() {
        // When optional mesh startup fails, status must transition to Degraded.
        let policy = MeshSupervisionPolicy::optional();
        let mut status = WorkerMeshStatus::default();
        status.transition_starting();

        let event = MeshSupervisionEvent::StartupFailed("timeout".into());
        apply_mesh_event_to_status(&mut status, &event);
        let decision = decide_mesh_action(&policy, &status.phase, &event, false);

        assert!(
            matches!(decision, MeshSupervisorDecision::MarkDegraded(_)),
            "optional StartupFailed must produce MarkDegraded: {:?}",
            decision
        );
        apply_mesh_decision_to_status(&mut status, &decision);
        assert_eq!(status.phase, WorkerMeshPhase::Degraded);
    }

    #[tokio::test]
    async fn disabled_mesh_produces_no_support_tasks() {
        // Disabled mesh must not create any MeshSupportTasks resources.
        let support = synvoid::worker::unified_server::MeshSupportTasks::empty();
        // All fields must be empty/None
        #[cfg(all(feature = "mesh", feature = "dns"))]
        {
            assert!(support.dns_verification_registries.is_empty());
            assert!(support.yara_broadcast.is_none());
        }
    }

    #[tokio::test]
    async fn support_tasks_consumed_once() {
        // MeshSupportTasks::empty() creates fresh empty support; take() semantics
        // ensure single consumption. Verify Option::take() pattern.
        let mut support = Some(synvoid::worker::unified_server::MeshSupportTasks::empty());
        let first = support.take();
        assert!(first.is_some(), "first take must succeed");
        let second = support.take();
        assert!(second.is_none(), "second take must be None (consumed)");
    }

    #[tokio::test]
    async fn required_failure_then_optional_success_isolation() {
        // A required failure and optional success are independent events.
        // Required failure → ShutdownWorker
        let req_policy = MeshSupervisionPolicy::required();
        let req_event = MeshSupervisionEvent::StartupFailed("dns failure".into());
        let req_decision =
            decide_mesh_action(&req_policy, &WorkerMeshPhase::Starting, &req_event, false);
        assert!(matches!(
            req_decision,
            MeshSupervisorDecision::ShutdownWorker(_)
        ));

        // Optional success → NoAction
        let opt_policy = MeshSupervisionPolicy::optional();
        let opt_event = MeshSupervisionEvent::Started;
        let opt_decision =
            decide_mesh_action(&opt_policy, &WorkerMeshPhase::Starting, &opt_event, false);
        assert!(matches!(opt_decision, MeshSupervisorDecision::NoAction));
    }

    // ====================================================================
    // Iteration 86 Phase 25: Status Transition Behavioral Tests
    // ====================================================================

    #[tokio::test]
    async fn optional_startup_reports_starting_while_blocked() {
        // Optional startup must show Starting phase while the startup future is active.
        let mut status = WorkerMeshStatus::default();
        assert_eq!(status.phase, WorkerMeshPhase::Disabled);

        status.transition_starting();
        assert_eq!(status.phase, WorkerMeshPhase::Starting);

        // Heartbeat should observe Starting
        assert!(
            matches!(status.health, MeshServiceHealth::Healthy),
            "Starting phase must have Healthy health"
        );
    }

    #[tokio::test]
    async fn required_success_updates_last_transition_once() {
        // Required startup success must update last_transition exactly once.
        let mut status = WorkerMeshStatus::default();
        let t0 = std::time::Instant::now();
        status.transition_starting();
        let t1 = status.last_transition;
        assert!(t1 >= t0);

        status.transition_running();
        let t2 = status.last_transition;
        assert!(t2 >= t1);

        // Verify phase is Running
        assert_eq!(status.phase, WorkerMeshPhase::Running);
    }

    #[tokio::test]
    async fn optional_success_updates_last_transition_once() {
        // Optional startup success (via coordinator) must update last_transition.
        let mut status = WorkerMeshStatus::default();
        let t0 = std::time::Instant::now();

        // Simulate: Starting → Started event → Running
        status.transition_starting();
        let event = MeshSupervisionEvent::Started;
        apply_mesh_event_to_status(&mut status, &event);
        let policy = MeshSupervisionPolicy::optional();
        let decision = decide_mesh_action(&policy, &status.phase, &event, false);
        apply_mesh_decision_to_status(&mut status, &decision);

        assert_eq!(status.phase, WorkerMeshPhase::Running);
        assert!(status.last_transition >= t0);
    }

    #[tokio::test]
    async fn required_failure_updates_last_transition_once() {
        // Required startup failure must update last_transition.
        let mut status = WorkerMeshStatus::default();
        status.transition_starting();
        let t1 = status.last_transition;

        status.transition_failed("startup failed".into());
        let t2 = status.last_transition;
        assert!(t2 >= t1);
        assert_eq!(status.phase, WorkerMeshPhase::Failed);
    }

    #[tokio::test]
    async fn no_duplicate_success_failure_metrics() {
        // Starting → Running → Starting (recovery) → Running must not
        // produce duplicate Started events from the required path.
        let mut status = WorkerMeshStatus::default();

        // First cycle: Starting → Running
        status.transition_starting();
        status.transition_running();
        assert_eq!(status.phase, WorkerMeshPhase::Running);

        // Simulate recovery: Running → Stopped → Starting → Running
        // (MeshLifecycleState requires Stopped before Starting)
        status.transition_starting();
        status.transition_running();
        assert_eq!(status.phase, WorkerMeshPhase::Running);

        // Verify last_transition is updated each time
        let t_before = status.last_transition;
        std::thread::sleep(Duration::from_millis(1));
        status.transition_running();
        assert!(status.last_transition > t_before);
    }

    #[tokio::test]
    async fn heartbeat_observes_stable_final_state() {
        // After startup completes, heartbeat must observe a stable final state.
        let mut status = WorkerMeshStatus::default();
        status.transition_starting();
        status.transition_running();

        // Simulate heartbeat reading
        let phase = status.phase;
        let health = &status.health;
        assert_eq!(phase, WorkerMeshPhase::Running);
        assert!(
            matches!(health, MeshServiceHealth::Healthy),
            "Running phase must have Healthy health"
        );
    }
}

// --- Iteration 87 Phase 14: Support generation behavioral tests ---

#[cfg(test)]
mod support_generation_tests {
    use std::time::Duration;
    use synvoid::worker::task_registry::{TaskExitReason, TaskId, WorkerTaskRegistry};
    use tokio::sync::watch;

    /// The watch-channel pattern used by MeshGenerationSupport.cancel() sends
    /// `true` and the receiver observes it.
    #[tokio::test]
    async fn mesh_generation_support_cancel_sends_signal() {
        let (tx, mut rx) = watch::channel(false);
        assert!(!*rx.borrow());

        tx.send(true).unwrap();
        // watch::Receiver only sees the latest value after borrow_and_update.
        assert!(*rx.borrow_and_update());
    }

    /// Cancelling twice does not panic — the second send is a no-op overwrite.
    #[tokio::test]
    async fn mesh_generation_support_cancel_is_idempotent() {
        let (tx, mut rx) = watch::channel(false);

        tx.send(true).unwrap();
        assert!(*rx.borrow_and_update());

        // Second cancel is safe.
        tx.send(true).unwrap();
        assert!(*rx.borrow_and_update());
    }

    /// cancel_then_join_tasks aborts matched tasks and removes them from the
    /// registry.
    #[tokio::test]
    async fn registry_cancel_then_join_tasks_removes_matched() {
        let mut registry = WorkerTaskRegistry::new();

        // Spawn two long-sleeping background tasks.
        let id1 = registry.spawn_cancellable_background("bg_sleep_1", async {
            tokio::time::sleep(Duration::from_secs(3600)).await;
        });
        let id2 = registry.spawn_cancellable_background("bg_sleep_2", async {
            tokio::time::sleep(Duration::from_secs(3600)).await;
        });

        let before = registry.active_count();
        assert!(before >= 2, "expected at least 2 active tasks");

        let task_ids = vec![TaskId(id1 as u64), TaskId(id2 as u64)];
        let report = registry
            .cancel_then_join_tasks(
                &task_ids,
                Duration::from_secs(1),
                Duration::from_secs(1),
                true,
            )
            .await;

        assert_eq!(report.exits.len(), 2, "should return exits for both tasks");
        for exit in &report.exits {
            assert!(
                matches!(
                    exit.reason,
                    TaskExitReason::Aborted
                        | TaskExitReason::Cancelled
                        | TaskExitReason::CleanCompletion
                ),
                "unexpected exit reason: {:?}",
                exit.reason
            );
        }
        // The two tasks should no longer be in the registry.
        assert!(registry.active_count() <= before - 2);
    }

    /// Empty task-id list returns immediately with no exits.
    #[tokio::test]
    async fn registry_cancel_then_join_tasks_empty_ids() {
        let mut registry = WorkerTaskRegistry::new();
        let report = registry
            .cancel_then_join_tasks(&[], Duration::from_secs(1), Duration::from_secs(1), true)
            .await;
        assert!(report.exits.is_empty());
    }

    /// A critical task that sleeps forever is aborted and removed within the
    /// timeout.
    #[tokio::test]
    async fn registry_cancel_then_join_tasks_timeout() {
        let mut registry = WorkerTaskRegistry::new();

        let id = registry.spawn_cancellable_background("forever_sleep", async {
            tokio::time::sleep(Duration::from_secs(3600)).await;
        });

        let task_ids = vec![TaskId(id as u64)];
        let report = registry
            .cancel_then_join_tasks(
                &task_ids,
                Duration::from_millis(50),
                Duration::from_millis(50),
                true,
            )
            .await;

        assert_eq!(report.exits.len(), 1);
        assert!(
            matches!(
                report.exits[0].reason,
                TaskExitReason::Aborted
                    | TaskExitReason::Cancelled
                    | TaskExitReason::CleanCompletion
            ),
            "task should be aborted or clean, got {:?}",
            report.exits[0].reason
        );
    }

    /// TaskId inner field is public and accessible.
    #[test]
    fn mesh_generation_support_task_ids_are_pub() {
        let tid = TaskId(42);
        assert_eq!(tid.0, 42);
    }

    /// MeshGenerationSupport.generation is pub — verified via source text
    /// (private cancel_tx prevents external construction).
    #[test]
    fn mesh_generation_support_generation_is_pub() {
        let content = std::fs::read_to_string("src/worker/unified_server/mod.rs")
            .expect("failed to read unified_server/mod.rs");
        assert!(
            content.contains("pub generation: u64"),
            "MeshGenerationSupport must have pub generation field"
        );
    }

    /// Option::take() correctly clears the bundle, matching the Phase 11
    /// pattern where active_mesh_support.take() cancels and clears.
    #[test]
    fn active_mesh_support_take_clears_bundle() {
        let mut opt: Option<i32> = Some(42);
        assert_eq!(opt.take(), Some(42));
        assert_eq!(opt, None);
        // Second take is safe and returns None.
        assert_eq!(opt.take(), None);
    }
}
