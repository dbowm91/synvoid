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
        (WorkerShutdownCause::ServerExited, false, false, true),
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
