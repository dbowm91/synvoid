//! Root-test ownership: COMPOSITION
//! Rationale: validates fault injection across supervisor, block-store, and plugin crates
//!
//! Failure-injection tests for SynVoid subsystems.
//!
//! Each test injects a specific failure into a subsystem and verifies
//! that the system fails gracefully: correct error types, correct state,
//! no panics, and appropriate fallback behavior.
//!
//! These are unit/integration tests — no full process spawning required.

use std::net::IpAddr;
use std::time::Duration;

use synvoid_block_store::{
    BlockStore, BlocklistCatchupResult, BlocklistEventCursor, BlocklistEventLog,
};
use synvoid_config::DenyListLimitsConfig;
use synvoid_core::block_store::{BlockProvenance, BlockTargetKind, BlocklistEvent};

// ─── Test 1: Supervisor critical task failure counted in shutdown report ─────

/// Inject a failure into a `SupervisorTaskRegistry` by registering a task
/// that returns `SupervisorTaskOutcome::Failed`. Verify that
/// `shutdown_and_join` counts it in the `failed` field of the report.
#[tokio::test]
async fn supervisor_critical_task_failure_counted_in_shutdown_report() {
    use synvoid::supervisor::task_registry::{
        SupervisorTaskClass, SupervisorTaskOutcome, SupervisorTaskRegistry,
    };

    let mut registry = SupervisorTaskRegistry::new();

    // Register a task that immediately fails.
    registry.register(
        "failing_task",
        SupervisorTaskClass::CriticalControlPlane,
        tokio::spawn(async { SupervisorTaskOutcome::Failed("injected failure".to_string()) }),
    );

    // Register a task that completes successfully.
    registry.register(
        "healthy_task",
        SupervisorTaskClass::BestEffortMaintenance,
        tokio::spawn(async { SupervisorTaskOutcome::Completed }),
    );

    // Let spawned tasks actually run.
    tokio::time::sleep(Duration::from_millis(50)).await;

    let report = registry.shutdown_and_join(Duration::from_secs(5)).await;

    assert_eq!(
        report.failed, 1,
        "Expected 1 failed task, got {}",
        report.failed
    );
    assert_eq!(
        report.completed, 1,
        "Expected 1 completed task, got {}",
        report.completed
    );
    assert_eq!(
        registry.active_count(),
        0,
        "Registry should be empty after shutdown"
    );
}

// ─── Test 2: Supervisor task failure maps to SupervisorShutdownCause::TaskFailed

/// Verify that a `SupervisorShutdownCause::TaskFailed` variant carries the
/// correct task name, reason, and is classified as fatal.
#[test]
fn supervisor_shutdown_cause_task_failed_is_fatal_with_correct_metadata() {
    use synvoid::supervisor::shutdown::SupervisorShutdownCause;

    let cause = SupervisorShutdownCause::TaskFailed {
        task: "mesh_sync",
        reason: "DHT lookup timed out".to_string(),
    };

    // TaskFailed must be fatal (triggers restart/alerting).
    assert!(cause.is_fatal(), "TaskFailed should be fatal");

    // Metric label must be stable for dashboards.
    assert_eq!(cause.metric_label(), "task_failed");

    // Display must include both task name and reason.
    let display = format!("{}", cause);
    assert!(
        display.contains("mesh_sync"),
        "Display should include task name: {}",
        display
    );
    assert!(
        display.contains("DHT lookup timed out"),
        "Display should include reason: {}",
        display
    );
}

// ─── Test 3: Blocklist catchup cursor beyond retained history → snapshot_required

/// Create a `BlocklistEventLog` with small capacity (5 events). Append 10
/// events so the oldest 5 are evicted. Query with a cursor pointing into
/// the evicted range. Verify `snapshot_required: true` and
/// `history_complete: false`, indicating the caller must fall back to a
/// full snapshot.
#[test]
fn blocklist_catchup_cursor_beyond_retained_history_requests_snapshot() {
    let mut log = BlocklistEventLog::new(5);

    // Append 10 events (sequences 0..9).
    let now = synvoid_utils::safe_unix_timestamp();
    for i in 0..10 {
        let event = BlocklistEvent::block_ip(
            &format!("10.0.0.{}", i),
            "test",
            "global",
            BlockProvenance::default(),
            now + i,
        );
        log.append(event);
    }

    // The log retains sequences 5..9 (5 events). Sequence 0..4 are evicted.
    // Query from sequence 3 — this points into evicted history.
    let cursor = BlocklistEventCursor {
        since_sequence: Some(3),
        max_events: 100,
    };

    let result: BlocklistCatchupResult = log.query_since(&cursor);

    assert!(
        !result.history_complete,
        "History should be incomplete since cursor 3 < oldest retained 5"
    );
    assert!(
        result.snapshot_required,
        "snapshot_required should be true when cursor is before oldest retained event"
    );
    // Should still return the events we do have (sequences 5..9).
    assert_eq!(
        result.events.len(),
        5,
        "Should return all 5 retained events"
    );
}

// ─── Test 4: Blocklist snapshot apply rejects stale records via target state

/// Apply an Unblock event via `apply_blocklist_event` to establish target
/// state. Then apply a snapshot chunk containing an older Block for the
/// same target. Verify the snapshot Block is rejected as stale because
/// the Unblock tombstone is newer — preventing stale replay from
/// resurrecting a removed block.
#[test]
fn blocklist_snapshot_apply_rejects_stale_records_via_target_state() {
    let store = BlockStore::new(true, None, DenyListLimitsConfig::default());
    let now = synvoid_utils::safe_unix_timestamp();

    // Step 1: Establish a Block first, then Unblock it at a high timestamp.
    // This creates target state with operation=Unblock, preventing resurrection.
    let block_event = BlocklistEvent::block_ip(
        "192.168.1.100",
        "initial_block",
        "global",
        BlockProvenance::default(),
        now,
    );
    let block_result = store.apply_blocklist_event(&block_event);
    assert_eq!(
        block_result,
        synvoid_block_store::BlocklistApplyResult::Applied,
        "Initial block should be applied"
    );

    let unblock_event = BlocklistEvent::unblock_ip(
        "192.168.1.100",
        "global",
        BlockProvenance::default(),
        now + 200, // Newer timestamp
    );
    let unblock_result = store.apply_blocklist_event(&unblock_event);
    assert_eq!(
        unblock_result,
        synvoid_block_store::BlocklistApplyResult::Applied,
        " Unblock should be applied"
    );

    // Step 2: Try to apply a snapshot with an older Block for the same target.
    // The snapshot should be rejected because the Unblock tombstone is newer.
    let snapshot = synvoid_core::block_store::BlocklistSnapshotChunk {
        ip_blocks: vec![synvoid_core::block_store::BlockRecord {
            target_kind: BlockTargetKind::Ip,
            identifier: "192.168.1.100".to_string(),
            reason: "stale_snapshot_block".to_string(),
            blocked_at: now, // Older than the Unblock at now+200
            ban_expire_seconds: 3600,
            site_scope: "global".to_string(),
            access_count: 0,
            last_access: now,
            provenance: BlockProvenance::default(),
        }],
        mesh_blocks: vec![],
        target_state_records: vec![],
        next_page_token: None,
        has_more: false,
        snapshot_complete: true,
        truncated_reason: None,
    };

    let snapshot_result = store.apply_blocklist_snapshot(&snapshot);

    assert_eq!(
        snapshot_result.stale_records_ignored, 1,
        "Stale snapshot Block should be ignored (Unblock tombstone is newer)"
    );
    assert_eq!(
        snapshot_result.ip_blocks_applied, 0,
        "Stale record should not be applied"
    );

    // Verify the IP is NOT blocked — the Unblock should still be in effect.
    let ip: IpAddr = "192.168.1.100".parse().unwrap();
    assert!(
        store.is_blocked(&ip, "global").is_none(),
        "IP should remain unblocked after stale snapshot rejection"
    );
}

// ─── Test 5: Plugin load failure returns error, manager remains usable

/// Attempt to load a WASM plugin from a nonexistent path. Verify that
/// `WasmPluginError::LoadFailed` is returned and the plugin manager
/// is still functional for subsequent operations.
#[test]
fn plugin_load_failure_returns_error_manager_remains_usable() {
    use synvoid_plugin_runtime::plugin_manager::PluginManager;
    use synvoid_plugin_runtime::wasm_runtime::WasmPluginError;

    let manager = PluginManager::new();

    // Attempt to load a nonexistent plugin.
    let result = manager.load_wasm_plugin(std::path::Path::new("/nonexistent/fake_plugin.wasm"));

    match result {
        Err(WasmPluginError::LoadFailed(msg)) => {
            // Error message should indicate the failure reason.
            assert!(
                !msg.is_empty(),
                "LoadFailed error message should not be empty"
            );
        }
        Err(other) => {
            panic!("Expected WasmPluginError::LoadFailed, got: {:?}", other);
        }
        Ok(_) => {
            panic!("Loading a nonexistent plugin should fail");
        }
    }

    // Manager should still be usable — no internal state corruption.
    // Verify we can call list_plugins (returns empty since nothing loaded).
    assert!(
        manager.wasm_manager().list_plugins().is_empty(),
        "Plugin list should be empty after failed load"
    );

    // Verify a second load attempt with another nonexistent path also
    // fails gracefully (no poisoned state).
    let result2 =
        manager.load_wasm_plugin(std::path::Path::new("/nonexistent/another_plugin.wasm"));
    assert!(
        result2.is_err(),
        "Second load attempt should also fail gracefully"
    );
}

// ─── Test 6: Worker critical task panic classified as TaskExitReason::Panic

/// Register a critical task that panics in `WorkerTaskRegistry`. Verify
/// that the exit notification carries `TaskExitReason::Panic` with the
/// correct message, and that the registry reports it as abnormal.
#[tokio::test]
async fn worker_critical_task_panic_classified_as_panic_exit() {
    use synvoid::worker::task_registry::{TaskExitReason, WorkerTaskRegistry};

    let mut registry = WorkerTaskRegistry::new();
    let mut exit_rx = registry.subscribe_exits();

    registry.spawn_critical("critical_panic_test", async {
        panic!("injected critical failure");
    });

    // The exit notification should arrive promptly.
    let exit = tokio::time::timeout(Duration::from_secs(2), exit_rx.recv())
        .await
        .expect("Should receive exit notification within timeout")
        .expect("Broadcast channel should be open");

    assert_eq!(exit.name, "critical_panic_test");

    match &exit.reason {
        TaskExitReason::Panic(msg) => {
            assert!(
                msg.contains("injected critical failure"),
                "Panic message should contain the injected text: {}",
                msg
            );
        }
        other => {
            panic!("Expected TaskExitReason::Panic, got: {:?}", other);
        }
    }

    // Panic exits are abnormal.
    assert!(
        exit.reason.is_abnormal(),
        "Panic should be classified as abnormal"
    );

    // Shutdown should still complete cleanly.
    let exits = registry
        .shutdown_and_join(Duration::from_secs(2), Duration::from_secs(2))
        .await;
    assert_eq!(registry.active_count(), 0);
    // The panic exit may appear in shutdown exits too, but registry should be clean.
    let _ = exits; // Just verify no panic during shutdown.
}

// ─── Test 7: Blocklist event log deduplication prevents double-application

/// Append the same blocklist event (by event_id) twice to the event log.
/// Verify the second append is a no-op and the log retains only one copy.
#[test]
fn blocklist_event_log_deduplication_prevents_double_insertion() {
    let mut log = BlocklistEventLog::new(100);
    let now = synvoid_utils::safe_unix_timestamp();

    let event = BlocklistEvent::block_ip(
        "10.0.0.1",
        "duplicate_test",
        "global",
        BlockProvenance::default(),
        now,
    )
    .with_event_id("unique-event-001".to_string());

    // First append should succeed and return sequence 0.
    let seq1 = log.append(event.clone());
    assert_eq!(seq1, Some(0), "First append should return sequence 0");

    // Second append with same event_id should be a no-op.
    let seq2 = log.append(event);
    assert_eq!(seq2, None, "Duplicate event_id should return None (no-op)");

    // Log should have exactly 1 event.
    assert_eq!(
        log.len(),
        1,
        "Log should contain exactly 1 event after dedup"
    );

    // Query should return exactly 1 event.
    let cursor = BlocklistEventCursor {
        since_sequence: None,
        max_events: 100,
    };
    let result = log.query_since(&cursor);
    assert_eq!(
        result.events.len(),
        1,
        "Query should return exactly 1 event"
    );
}

// ─── Test 8: Worker task registry aborts spinning tasks within timeout

/// Register multiple long-running spinning tasks, then shut down with
/// a tight timeout. Verify all tasks are aborted and the registry is
/// empty afterward — no task leak.
#[tokio::test]
async fn worker_task_registry_no_task_leak_on_shutdown_timeout() {
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;
    use synvoid::worker::task_registry::{TaskExitReason, WorkerTaskRegistry};

    let mut registry = WorkerTaskRegistry::new();
    let counter = Arc::new(AtomicU64::new(0));

    // Spawn 5 background tasks that spin forever.
    for _ in 0..5 {
        let c = counter.clone();
        registry.spawn_background("spinner", async move {
            loop {
                c.fetch_add(1, Ordering::Relaxed);
                tokio::time::sleep(Duration::from_millis(5)).await;
            }
        });
    }

    assert_eq!(registry.background_count(), 5);

    // Shutdown with a very short timeout — tasks should be aborted.
    let exits = registry
        .shutdown_and_join(Duration::from_millis(100), Duration::from_millis(100))
        .await;

    // All 5 tasks should have been aborted.
    assert_eq!(
        exits.len(),
        5,
        "All 5 spinning tasks should appear in exits"
    );
    for exit in &exits {
        assert_eq!(
            exit.reason,
            TaskExitReason::Aborted,
            "Spinning task {} should be aborted, got {:?}",
            exit.name,
            exit.reason
        );
    }

    // Registry should be completely empty — no task leak.
    assert_eq!(
        registry.active_count(),
        0,
        "Registry should have 0 active tasks after shutdown"
    );

    // Verify tasks actually stopped.
    let after = counter.load(Ordering::Relaxed);
    tokio::time::sleep(Duration::from_millis(50)).await;
    let after_wait = counter.load(Ordering::Relaxed);
    assert!(
        after_wait <= after + 2,
        "Tasks should have stopped after abort: after={}, after_wait={}",
        after,
        after_wait
    );
}

// ─── Test 9: BlockStore disabled → all operations are no-ops

/// Create a `BlockStore` with `enabled: false`. Verify that block_ip,
/// is_blocked, unblock_ip, and apply_blocklist_event all return
/// gracefully without mutating state.
#[test]
fn blockstore_disabled_all_operations_are_noop() {
    let store = BlockStore::new(false, None, DenyListLimitsConfig::default());
    let ip: IpAddr = "10.0.0.1".parse().unwrap();

    // block_ip returns false when disabled.
    assert!(
        !store.block_ip(ip, "test", 3600, "global"),
        "block_ip should return false when store is disabled"
    );

    // is_blocked returns None when disabled.
    assert!(
        store.is_blocked(&ip, "global").is_none(),
        "is_blocked should return None when store is disabled"
    );

    // unblock_ip returns false when disabled.
    assert!(
        !store.unblock_ip(&ip, "global"),
        "unblock_ip should return false when store is disabled"
    );

    // apply_blocklist_event returns StoreDisabled.
    let event = BlocklistEvent::block_ip(
        "10.0.0.1",
        "test",
        "global",
        BlockProvenance::default(),
        synvoid_utils::safe_unix_timestamp(),
    );
    let result = store.apply_blocklist_event(&event);
    assert_eq!(
        result,
        synvoid_block_store::BlocklistApplyResult::StoreDisabled,
        "apply_blocklist_event should return StoreDisabled when disabled"
    );

    // Snapshot apply returns default (all zeros).
    let snapshot = synvoid_core::block_store::BlocklistSnapshotChunk {
        ip_blocks: vec![synvoid_core::block_store::BlockRecord {
            target_kind: BlockTargetKind::Ip,
            identifier: "10.0.0.2".to_string(),
            reason: "test".to_string(),
            blocked_at: 0,
            ban_expire_seconds: 3600,
            site_scope: "global".to_string(),
            access_count: 0,
            last_access: 0,
            provenance: BlockProvenance::default(),
        }],
        mesh_blocks: vec![],
        target_state_records: vec![],
        next_page_token: None,
        has_more: false,
        snapshot_complete: true,
        truncated_reason: None,
    };
    let snap_result = store.apply_blocklist_snapshot(&snapshot);
    assert_eq!(
        snap_result.ip_blocks_applied, 0,
        "Snapshot apply should produce 0 applied when disabled"
    );
}

// ─── Test 10: SupervisorShutdownCause non-fatal variants are correct

/// Verify that `Requested` and `DrainTimeout` are the only non-fatal
/// shutdown causes, and that all other variants are fatal. This guards
/// against accidentally adding a non-fatal variant without updating
/// the exit code logic.
#[test]
fn supervisor_shutdown_cause_fatal_classification_is_complete() {
    use synvoid::supervisor::shutdown::SupervisorShutdownCause;

    let all_causes = vec![
        SupervisorShutdownCause::Requested,
        SupervisorShutdownCause::DrainTimeout,
        SupervisorShutdownCause::IpcListenerFailed("test".into()),
        SupervisorShutdownCause::ControlApiFailed("test".into()),
        SupervisorShutdownCause::WorkerHealthFatal("test".into()),
        SupervisorShutdownCause::ProcessManagerFailed("test".into()),
        SupervisorShutdownCause::TaskFailed {
            task: "test",
            reason: "test".into(),
        },
        SupervisorShutdownCause::InternalInvariant("test".into()),
    ];

    for cause in &all_causes {
        let is_non_fatal = matches!(
            cause,
            SupervisorShutdownCause::Requested | SupervisorShutdownCause::DrainTimeout
        );
        assert_eq!(
            cause.is_fatal(),
            !is_non_fatal,
            "{:?} should have is_fatal={} but got is_fatal={}",
            cause,
            !is_non_fatal,
            cause.is_fatal()
        );
    }
}
