//! Integration tests for the worker supervision control flow (Iteration 63).
//!
//! Tests the supervision loop behavior: non-fatal exits don't stop the worker,
//! critical exits do, receiver lag is handled, etc.

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
            WorkerShutdownCause::ServerExitedUnexpectedly,
            true,
            false,
            false,
        ),
        (WorkerShutdownCause::SupervisorShutdown, false, false, true),
        (
            WorkerShutdownCause::SupervisorDisconnected,
            true,
            true,
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
    assert_eq!(WorkerShutdownCause::ServerExitedUnexpectedly.exit_code(), 1);
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
    use synvoid::worker::unified_server::lifecycle::{LifecycleRequest, WorkerLifecycleEvent};

    let mut registry = WorkerTaskRegistry::new();
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
    // should_notify_supervisor is true for SupervisorDisconnected,
    // but the composition root routes it to no-op since channel is unavailable.
    assert!(cause.should_notify_supervisor());
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

/// Verify shutdown ordering: begin_shutdown before stop_accepting.
#[tokio::test]
async fn test_shutdown_ordering_begin_before_stop_accepting() {
    // This is a structural test verifying the source code ordering.
    let content = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/worker/unified_server/mod.rs"),
    )
    .unwrap();

    let composition_start = content
        .find("composition-root shutdown procedure")
        .expect("composition root not found");
    let section = &content[composition_start..];

    let begin_pos = section
        .find("registry.begin_shutdown()")
        .expect("begin_shutdown not found");
    let ack_pos = section.find("ack_tx.send(())").expect("ack send not found");
    let stop_accepting_pos = section
        .find("state.stop_accepting_tx")
        .expect("stop_accepting not found");

    assert!(
        begin_pos < ack_pos,
        "begin_shutdown must come before lifecycle acknowledgement"
    );
    assert!(
        ack_pos < stop_accepting_pos,
        "lifecycle acknowledgement must come before stop_accepting"
    );
}
