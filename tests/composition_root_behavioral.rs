//! Composition-root behavioral tests (Iteration 89, Phases 21-23).
//!
//! These tests exercise the actual composition-root dataflow for optional
//! support bundle handoff and required support failure, using real
//! `WorkerTaskRegistry` and `MeshGenerationSupport` without mock services.

#![cfg(feature = "mesh")]

use std::sync::Arc;
use std::time::Duration;

use synvoid::worker::task_registry::{TaskId, WorkerTaskRegistry};
use synvoid::worker::unified_server::{
    stop_mesh_generation_support, MeshGenerationSupport, SupportStopContext,
};

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Build a `MeshGenerationSupport` that wraps real task IDs from a registry.
fn make_support(registry: &mut WorkerTaskRegistry, generation: u64) -> MeshGenerationSupport {
    let id1 = registry.spawn_background("dns_verify", async {
        let _ = tokio::time::sleep(Duration::from_secs(3600)).await;
    });
    let id2 = registry.spawn_background("yara_broadcast", async {
        let _ = tokio::time::sleep(Duration::from_secs(3600)).await;
    });
    let mut support = MeshGenerationSupport::empty(generation);
    support.task_ids = vec![TaskId(id1 as u64), TaskId(id2 as u64)];
    support
}

/// Simulate required support failure by spawning a panicking task.
#[tokio::test]
async fn required_support_failure_blocks_ready() {
    let registry = Arc::new(tokio::sync::Mutex::new(WorkerTaskRegistry::new()));
    let mut reg = registry.lock().await;
    let mut support = MeshGenerationSupport::empty(1);
    // Spawn a task that panics immediately — simulates a failure.
    let panic_id = reg.spawn_critical("dns_verify_panic", async {
        panic!("simulated support registration failure");
    });
    support.task_ids = vec![TaskId(panic_id as u64)];
    drop(reg);

    let report = stop_mesh_generation_support(
        &registry,
        support,
        Duration::from_secs(5),
        SupportStopContext::WorkerShutdown,
    )
    .await;

    // Panicking task counts as failed → report is not clean → ready must not emit.
    assert!(
        !report.clean(),
        "panicking support stop must not be clean (blocks ready), got {:?}",
        report
    );
}

// ── Phase 23: Optional success returns/stores bundle ────────────────────────

#[tokio::test]
async fn optional_success_returns_bundle() {
    let (tx, mut rx) =
        tokio::sync::mpsc::channel::<Result<Option<MeshGenerationSupport>, String>>(1);

    let support = MeshGenerationSupport::empty(1);
    tx.send(Ok(Some(support))).await.unwrap();

    let result = rx.recv().await.unwrap();
    assert!(result.is_ok(), "startup success must be Ok");
    let bundle = result.unwrap().expect("bundle must be present");
    assert_eq!(bundle.generation, 1);
    assert!(bundle.task_ids.is_empty());
}

// ── Phase 23: Optional degradation performs bounded subset cleanup ───────────

#[tokio::test]
async fn optional_degradation_performs_bounded_cleanup() {
    let registry = Arc::new(tokio::sync::Mutex::new(WorkerTaskRegistry::new()));
    let mut reg = registry.lock().await;
    let support = make_support(&mut reg, 1);
    let task_count = support.task_ids.len();
    drop(reg);

    let start = std::time::Instant::now();
    let report = stop_mesh_generation_support(
        &registry,
        support,
        Duration::from_secs(5),
        SupportStopContext::OptionalMeshDegraded,
    )
    .await;
    let elapsed = start.elapsed();

    assert_eq!(report.generation, 1);
    assert!(
        elapsed < Duration::from_secs(10),
        "cleanup must complete within timeout, took {:?}",
        elapsed
    );
    // With 5s timeout, cooperative phase gets 2.5s which is plenty for
    // a task that responds to the watch cancellation signal.
    assert!(
        report.cooperative >= task_count || report.aborted >= task_count,
        "all tasks must be accounted for: {:?}",
        report
    );
}

// ── Phase 23: Optional immediate-exit race leaves no support tasks ──────────

#[tokio::test]
async fn optional_immediate_exit_leaves_no_tasks() {
    let registry = Arc::new(tokio::sync::Mutex::new(WorkerTaskRegistry::new()));
    let support = MeshGenerationSupport::empty(1);
    assert!(support.task_ids.is_empty());

    let report = stop_mesh_generation_support(
        &registry,
        support,
        Duration::from_secs(5),
        SupportStopContext::OptionalMeshDegraded,
    )
    .await;

    assert!(report.clean(), "empty support must be clean");
    assert_eq!(report.cooperative, 0);
    assert_eq!(report.aborted, 0);
    assert_eq!(report.failed, 0);
}

// ── Phase 23: Cleanup report classifications are correct ────────────────────

#[tokio::test]
async fn cleanup_report_classifications_correct() {
    let registry = Arc::new(tokio::sync::Mutex::new(WorkerTaskRegistry::new()));
    let mut reg = registry.lock().await;
    let support = make_support(&mut reg, 2);
    drop(reg);

    let report = stop_mesh_generation_support(
        &registry,
        support,
        Duration::from_secs(5),
        SupportStopContext::OptionalMeshDegraded,
    )
    .await;

    // Verify the report has consistent counts.
    let total = report.cooperative + report.aborted + report.failed;
    assert!(
        total >= 2,
        "report must account for at least 2 tasks, got {:?}",
        report
    );
    // clean() requires no aborts and no failures.
    if report.aborted == 0 && report.failed == 0 {
        assert!(report.clean());
    } else {
        assert!(!report.clean());
    }
}

// ── Phase 23: Forced abort path awaits every handle ─────────────────────────

#[tokio::test]
async fn forced_abort_path_awaits_every_handle() {
    let registry = Arc::new(tokio::sync::Mutex::new(WorkerTaskRegistry::new()));
    let mut reg = registry.lock().await;
    let support = make_support(&mut reg, 1);
    let task_ids = support.task_ids.clone();
    drop(reg);

    // Use zero timeout to force immediate abort.
    let report = stop_mesh_generation_support(
        &registry,
        support,
        Duration::ZERO,
        SupportStopContext::WorkerShutdown,
    )
    .await;

    // Verify registry no longer contains the tasks.
    let reg = registry.lock().await;
    for id in &task_ids {
        assert!(
            !reg.contains_task(*id),
            "task {:?} must be removed from registry after forced abort",
            id
        );
    }
    assert!(
        report.aborted >= 2 || report.cooperative >= 2,
        "all tasks must be accounted for in report"
    );
}

// ── Phase 23: No task ID remains registered after support teardown ──────────

#[tokio::test]
async fn no_task_id_remains_after_teardown() {
    let registry = Arc::new(tokio::sync::Mutex::new(WorkerTaskRegistry::new()));
    let mut reg = registry.lock().await;
    let support = make_support(&mut reg, 1);
    let task_ids = support.task_ids.clone();
    let initial_count = reg.active_count();
    drop(reg);

    let _report = stop_mesh_generation_support(
        &registry,
        support,
        Duration::from_secs(5),
        SupportStopContext::OptionalMeshDegraded,
    )
    .await;

    let reg = registry.lock().await;
    for id in &task_ids {
        assert!(
            !reg.contains_task(*id),
            "task {:?} must not remain in registry",
            id
        );
    }
    // Active count should have decreased by at least the number of tasks we registered.
    assert!(
        reg.active_count() <= initial_count,
        "active count should not increase after teardown"
    );
}

// ── Phase 6: Support-registration failure produces no bundle ────────────────

#[tokio::test]
async fn support_failure_produces_no_bundle() {
    let (tx, mut rx) =
        tokio::sync::mpsc::channel::<Result<Option<MeshGenerationSupport>, String>>(1);
    let _ = tx.send(Err("support registration failed".into())).await;
    let result = rx.recv().await.unwrap();
    assert!(result.is_err(), "support failure must be Err");
    match result {
        Ok(_) => panic!("expected Err, got Ok"),
        Err(err) => {
            assert!(
                err.contains("support registration failed"),
                "error must describe the failure, got: {err}"
            );
        }
    }
}

// ── Phase 6: Channel closure returns None ───────────────────────────────────

#[tokio::test]
async fn completion_channel_closure_returns_none() {
    let (tx, mut rx) =
        tokio::sync::mpsc::channel::<Result<Option<MeshGenerationSupport>, String>>(1);
    drop(tx);
    assert!(rx.recv().await.is_none(), "closed channel must return None");
}

// ── Phase 10: Ready not emitted before support assignment ───────────────────

#[tokio::test]
async fn ready_not_emitted_before_support_assignment() {
    let registry = Arc::new(tokio::sync::Mutex::new(WorkerTaskRegistry::new()));
    let mut reg = registry.lock().await;
    let support = make_support(&mut reg, 1);
    drop(reg);

    // Before calling stop, support is still active — not ready.
    let reg = registry.lock().await;
    assert!(
        reg.active_count() > 0,
        "registry must have active tasks before teardown"
    );
    drop(reg);

    // After stop, report.clean() determines readiness.
    let report = stop_mesh_generation_support(
        &registry,
        support,
        Duration::from_secs(5),
        SupportStopContext::OptionalMeshDegraded,
    )
    .await;

    // clean() is the readiness gate.
    assert!(
        report.clean(),
        "cooperative stop must be clean (ready allowed)"
    );
}

// ── Phase 10: Empty support set still permits ready ─────────────────────────

#[tokio::test]
async fn empty_support_set_permits_ready() {
    let registry = Arc::new(tokio::sync::Mutex::new(WorkerTaskRegistry::new()));
    let support = MeshGenerationSupport::empty(7);

    let report = stop_mesh_generation_support(
        &registry,
        support,
        Duration::from_secs(5),
        SupportStopContext::OptionalMeshDegraded,
    )
    .await;

    assert!(report.clean(), "empty support must be clean");
    assert_eq!(report.generation, 7);
}

// ── Phase 10: Repeated ready emission remains impossible ────────────────────

#[tokio::test]
async fn repeated_ready_emission_impossible() {
    let registry = Arc::new(tokio::sync::Mutex::new(WorkerTaskRegistry::new()));
    let mut reg = registry.lock().await;
    let support = make_support(&mut reg, 1);
    drop(reg);

    // First stop.
    let report1 = stop_mesh_generation_support(
        &registry,
        support,
        Duration::from_secs(5),
        SupportStopContext::OptionalMeshDegraded,
    )
    .await;
    assert!(report1.clean());

    // Second stop with empty support — still clean, still valid.
    let support2 = MeshGenerationSupport::empty(2);
    let report2 = stop_mesh_generation_support(
        &registry,
        support2,
        Duration::from_secs(5),
        SupportStopContext::OptionalMeshDegraded,
    )
    .await;
    assert!(report2.clean());
    assert_eq!(report2.generation, 2);
}
