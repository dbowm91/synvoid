//! Root-test ownership: COMPOSITION
//! Rationale: proves the production supervisor IPC path for Unified Server
//! worker heartbeats end to end — a real `Message::UnifiedServerWorkerHeartbeat`
//! written on a real `IpcStream`, consumed by `handle_worker_connection`,
//! stored by `ProcessManager::handle_unified_server_worker_heartbeat`, read
//! through the generation-aware snapshot, and published by the
//! `synvoid.eggbench-telemetry.v2` bridge as Prometheus samples.
//!
//! Every message is injected on the wire. No test calls
//! `handle_unified_server_worker_heartbeat()` directly: the defect guarded
//! here was a *missing supervisor dispatch arm* plus a *missing identity
//! classification*, and only the real connection loop exercises both.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use synvoid::block_store::BlockStore;
use synvoid::supervisor::ipc::handle_worker_connection;
use synvoid::supervisor::state::{SupervisorState, SupervisorStateTrackers};
use synvoid::supervisor::telemetry_bridge::{
    BridgeAggregator, OwnerMetric, CONTRACT_ID, CONTRACT_SCHEMA_VERSION,
};
use synvoid_config::{ConfigManager, DenyListLimitsConfig};
use synvoid_ipc::ipc_transport::{IpcEndpoint, IpcListener, IpcStream};
use synvoid_ipc::manager::ProcessManagerConfig;
use synvoid_ipc::{IpcRateLimitConfig, Message, ProcessManager, WorkerId, WorkerMetricsPayload};

static SEQUENCE: AtomicU64 = AtomicU64::new(0);

fn next_sequence() -> u64 {
    SEQUENCE.fetch_add(1, Ordering::Relaxed)
}

/// Unique per-call endpoint name so tests in this binary never share a socket.
fn unique_endpoint() -> IpcEndpoint {
    IpcEndpoint::new(&format!(
        "sv-hb-dispatch-{}-{}",
        std::process::id(),
        next_sequence()
    ))
}

fn test_supervisor_state() -> SupervisorState {
    let config_dir = std::env::temp_dir().join(format!(
        "sv-hb-dispatch-cfg-{}-{}",
        std::process::id(),
        next_sequence()
    ));
    std::fs::create_dir_all(&config_dir).expect("config dir");
    SupervisorState::new(
        Arc::new(tokio::sync::RwLock::new(ConfigManager::new(config_dir))),
        SupervisorStateTrackers::default(),
        Arc::new(BlockStore::new(
            false,
            None,
            DenyListLimitsConfig::default(),
        )),
    )
}

fn test_process_manager(rate_limit: IpcRateLimitConfig) -> Arc<ProcessManager> {
    let config = ProcessManagerConfig {
        ipc_rate_limit: rate_limit,
        ..ProcessManagerConfig::default()
    };
    let (pm, _events) = ProcessManager::new(config, None);
    Arc::new(pm)
}

/// Poll `condition` until it holds. The supervisor loop consumes messages on
/// its own task, so a wire write is not observable synchronously.
async fn await_until<F>(what: &str, mut condition: F)
where
    F: FnMut() -> bool,
{
    let deadline = Instant::now() + Duration::from_secs(10);
    while Instant::now() < deadline {
        if condition() {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    panic!("timed out waiting for {what}");
}

async fn await_snapshot_change(pm: &ProcessManager, worker: WorkerId, what: &str) {
    await_until(what, || {
        pm.get_unified_server_worker_metrics(worker)
            .is_some_and(|m| m.total_requests > 0)
    })
    .await;
}

/// A worker-side IPC connection plus the supervisor task consuming it.
/// Dropping the worker stream ends the supervisor's receive loop.
struct WorkerConn {
    worker: IpcStream,
    supervisor: tokio::task::JoinHandle<()>,
}

impl WorkerConn {
    async fn start(pm: Arc<ProcessManager>, state: SupervisorState) -> Self {
        let endpoint = unique_endpoint();
        let listener = IpcListener::bind(&endpoint)
            .await
            .expect("bind IPC endpoint");

        let supervisor = tokio::spawn(async move {
            let supervisor_side = listener.accept().await.expect("accept worker");
            handle_worker_connection(supervisor_side, pm, state).await;
        });

        let worker = endpoint.connect().await.expect("connect worker");
        Self { worker, supervisor }
    }

    async fn send(&mut self, message: &Message) {
        self.worker.send(message).await.expect("send message");
    }

    /// Startup message with the real socket peer PID, so the supervisor binds
    /// this worker ID to this connection's identity.
    async fn bind_identity(&mut self, worker: WorkerId) {
        self.send(&Message::UnifiedServerWorkerStarted {
            id: worker,
            pid: std::process::id(),
            timestamp: 1_700_000_000,
        })
        .await;
    }

    async fn heartbeat(&mut self, worker: WorkerId, metrics: WorkerMetricsPayload) {
        self.send(&Message::UnifiedServerWorkerHeartbeat {
            id: worker,
            timestamp: 1_700_000_000,
            metrics,
        })
        .await;
    }
}

impl Drop for WorkerConn {
    fn drop(&mut self) {
        self.supervisor.abort();
    }
}

/// A distinctive, unmistakably non-default payload. `Default` is zero almost
/// everywhere, which is exactly what a never-routed heartbeat looks like.
fn distinctive_payload() -> WorkerMetricsPayload {
    WorkerMetricsPayload {
        total_requests: 424_242,
        blocked: 11,
        challenged: 22,
        proxied: 424_209,
        errors: 3,
        current_concurrent: 9,
        peak_concurrent: 17,
        avg_latency_ms: 12.5,
        p50_latency_ms: 8.0,
        p95_latency_ms: 33.0,
        p99_latency_ms: 91.0,
        uptime_secs: 1234,
        memory_bytes: 987_654_321,
        cpu_percent: 42.5,
        event_loop_lag_ms: 7,
        request_queue_time_ms: synvoid_metrics::TimingStatsPayload {
            avg_ms: 2.0,
            p50_ms: 1.0,
            p95_ms: 19.0,
            p99_ms: 27.0,
        },
        body_buffering_bytes_total: 8_675_309,
        offload_submissions_total: 1_337,
        offload_timeouts_total: 4,
        offload_rejections_total: 2,
        offload_fallbacks_total: 1,
        health_score: 91.5,
        active_connections: 23,
        restart_count: 1,
        ..Default::default()
    }
}

/// C1 + C2: a heartbeat written on the wire by a worker that completed startup
/// identity binding reaches the generation-aware snapshot with its exact
/// non-default values.
#[tokio::test]
async fn routed_heartbeat_reaches_generation_aware_snapshot_with_exact_values() {
    let pm = test_process_manager(IpcRateLimitConfig::default());
    let worker = WorkerId(3);
    assert_eq!(
        pm.register_unified_server_worker_record(worker, None),
        1,
        "first registration observes generation 1"
    );

    let mut conn = WorkerConn::start(pm.clone(), test_supervisor_state()).await;
    conn.bind_identity(worker).await;
    let payload = distinctive_payload();
    conn.heartbeat(worker, payload.clone()).await;

    await_snapshot_change(&pm, worker, "the routed heartbeat to be stored").await;

    let snapshot = pm.get_all_unified_server_worker_metrics_with_generation();
    assert_eq!(
        snapshot.len(),
        1,
        "the heartbeat must update exactly the registered worker record"
    );
    let entry = &snapshot[0];
    assert_eq!(entry.worker_id, worker);
    assert_eq!(
        entry.generation, 1,
        "generation identity must survive the routed heartbeat unchanged"
    );

    let m = &entry.metrics;
    assert_eq!(m.total_requests, 424_242);
    assert_eq!(m.memory_bytes, 987_654_321);
    assert_eq!(m.cpu_percent, 42.5);
    assert_eq!(m.event_loop_lag_ms, 7);
    assert_eq!(m.request_queue_time_ms.p95_ms, 19.0);
    assert_eq!(m.body_buffering_bytes_total, 8_675_309);
    assert_eq!(m.offload_submissions_total, 1_337);
    assert_eq!(m.offload_rejections_total, 2);
    assert_eq!(m.active_connections, 23);
    assert_eq!(
        payload.total_requests, m.total_requests,
        "the supervisor must not reinterpret payload values at dispatch"
    );
}

/// C1 (negative identity): a startup message that claims a PID other than the
/// socket peer PID is a spoofing attempt. The supervisor must tear the
/// connection down, and nothing that follows may become telemetry.
#[tokio::test]
async fn heartbeat_after_spoofed_startup_pid_is_rejected() {
    let pm = test_process_manager(IpcRateLimitConfig::default());
    let worker = WorkerId(4);
    pm.register_unified_server_worker_record(worker, None);

    let mut conn = WorkerConn::start(pm.clone(), test_supervisor_state()).await;
    conn.send(&Message::UnifiedServerWorkerStarted {
        id: worker,
        pid: std::process::id().wrapping_add(4242),
        timestamp: 1_700_000_000,
    })
    .await;
    conn.heartbeat(worker, distinctive_payload()).await;

    tokio::time::sleep(Duration::from_millis(750)).await;
    let stored = pm.get_unified_server_worker_metrics(worker);
    assert!(
        !stored.as_ref().is_some_and(|m| m.total_requests > 0),
        "a heartbeat on a spoofed connection must never be recorded, got {stored:?}"
    );
}

/// Per-worker classification, not the global fallback: with a per-worker
/// allowance of 1 msg/s and a very large global burst, the second heartbeat
/// inside one window is refused by `check_worker`. An unclassified message
/// would fall back to `check()`, which only drains the global bucket and
/// would have let it through.
#[tokio::test]
async fn heartbeat_uses_the_per_worker_rate_limit_bucket() {
    let pm = test_process_manager(IpcRateLimitConfig {
        max_messages_per_second: 1,
        max_burst: 10_000,
    });
    let worker = WorkerId(8);
    pm.register_unified_server_worker_record(worker, None);

    let mut conn = WorkerConn::start(pm.clone(), test_supervisor_state()).await;
    conn.bind_identity(worker).await;
    let payload = distinctive_payload();

    // The startup message consumes this window's per-worker allowance, so wait
    // for the limiter's 1s window to roll before the first heartbeat.
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    conn.heartbeat(worker, payload.clone()).await;
    await_snapshot_change(&pm, worker, "the first heartbeat").await;

    let mut second = payload.clone();
    second.total_requests = payload.total_requests + 1;
    conn.heartbeat(worker, second).await;
    tokio::time::sleep(Duration::from_millis(750)).await;

    let stored = pm
        .get_unified_server_worker_metrics(worker)
        .expect("registered worker");
    assert_eq!(
        stored.total_requests, payload.total_requests,
        "the over-limit heartbeat must be dropped by the per-worker bucket"
    );
}

/// C3: a second heartbeat in the same generation replaces the current absolute
/// snapshot while generation identity stays put. This protects the v2 bridge's
/// same-generation delta semantics.
#[tokio::test]
async fn later_same_generation_heartbeat_replaces_absolute_snapshot() {
    let pm = test_process_manager(IpcRateLimitConfig::default());
    let worker = WorkerId(5);
    pm.register_unified_server_worker_record(worker, None);

    let mut conn = WorkerConn::start(pm.clone(), test_supervisor_state()).await;
    conn.bind_identity(worker).await;

    let first = distinctive_payload();
    conn.heartbeat(worker, first.clone()).await;
    await_snapshot_change(&pm, worker, "the first heartbeat").await;

    let mut second = first.clone();
    second.total_requests = first.total_requests + 1_000;
    second.body_buffering_bytes_total = first.body_buffering_bytes_total + 2_048;
    second.offload_submissions_total = first.offload_submissions_total + 15;
    second.active_connections = 41;
    let expected = second.clone();
    conn.heartbeat(worker, second).await;
    await_until("the second heartbeat to replace the snapshot", || {
        pm.get_unified_server_worker_metrics(worker)
            .is_some_and(|m| m.total_requests == expected.total_requests)
    })
    .await;

    let snapshot = pm.get_all_unified_server_worker_metrics_with_generation();
    assert_eq!(snapshot.len(), 1);
    assert_eq!(
        snapshot[0].generation, 1,
        "a same-generation replacement must not advance generation"
    );
    let m = &snapshot[0].metrics;
    assert_eq!(m.total_requests, expected.total_requests);
    assert_eq!(m.active_connections, 41);
    assert_eq!(
        m.body_buffering_bytes_total, expected.body_buffering_bytes_total,
        "the absolute snapshot is replaced wholesale, never accumulated"
    );
}

/// C4: a heartbeat from a worker ID the supervisor does not own is ignored.
/// Telemetry must never invent a record so that a series merely looks alive.
#[tokio::test]
async fn heartbeat_for_unowned_worker_id_creates_no_record() {
    let pm = test_process_manager(IpcRateLimitConfig::default());
    let owned = WorkerId(6);
    pm.register_unified_server_worker_record(owned, None);

    let mut conn = WorkerConn::start(pm.clone(), test_supervisor_state()).await;
    conn.bind_identity(owned).await;

    let stranger = WorkerId(600);
    conn.bind_identity(stranger).await;
    conn.heartbeat(stranger, distinctive_payload()).await;
    tokio::time::sleep(Duration::from_millis(750)).await;

    assert_eq!(
        pm.get_unified_server_worker_count(),
        1,
        "an unowned heartbeat ID must not create a worker record"
    );
    let snapshot = pm.get_all_unified_server_worker_metrics_with_generation();
    assert_eq!(snapshot.len(), 1);
    assert_eq!(snapshot[0].worker_id, owned);
    assert_eq!(
        snapshot[0].metrics.total_requests, 0,
        "the owned worker has deliberately not sent a heartbeat"
    );
    assert!(pm.get_unified_server_worker_metrics(stranger).is_none());
}

/// Workstream D: the full composition chain — wire heartbeat -> supervisor IPC
/// dispatch -> `ProcessManager` worker metrics -> generation-aware snapshot ->
/// v2 telemetry bridge -> Prometheus exposition. At least one gauge and one
/// monotonic counter must carry the injected non-default value. Bounded
/// fixture, no wall-clock dependence.
#[tokio::test]
async fn routed_heartbeat_propagates_through_bridge_to_prometheus() {
    assert_eq!(CONTRACT_ID, "synvoid.eggbench-telemetry.v2");
    assert_eq!(
        CONTRACT_SCHEMA_VERSION,
        "synvoid.eggbench-telemetry.contract.v2"
    );

    let (handle, _exporter_future) =
        synvoid::supervisor::telemetry_bridge::install_recorder_and_exporter(
            "127.0.0.1:0".parse().expect("loopback bind addr"),
        )
        .expect("install bridge recorder");
    synvoid::supervisor::telemetry_bridge::register_inventory(&handle);

    let pm = test_process_manager(IpcRateLimitConfig::default());
    let worker = WorkerId(7);
    pm.register_unified_server_worker_record(worker, None);

    let mut conn = WorkerConn::start(pm.clone(), test_supervisor_state()).await;
    conn.bind_identity(worker).await;

    let payload = distinctive_payload();
    conn.heartbeat(worker, payload.clone()).await;
    await_snapshot_change(&pm, worker, "the routed heartbeat to reach ProcessManager").await;

    // First refresh seeds the bridge's monotonic truth from the routed
    // heartbeat: no direct ProcessManager write, no cadence wait.
    let mut aggregator = BridgeAggregator::new();
    let first = aggregator.refresh(&pm, &handle);

    assert_eq!(
        first.active_connections, 23,
        "the gauge must be worker-backed, not the inventory default"
    );
    assert_eq!(first.worker_memory_bytes, 987_654_321);
    assert_eq!(first.event_loop_lag_ms, 7);
    assert_eq!(first.request_queue_p95_ms, 19);
    assert_eq!(first.worker_cpu_percent, 42.5);
    assert_eq!(first.body_buffering_bytes_total, 8_675_309);
    assert_eq!(first.offload_submissions_total, 1_337);
    assert_eq!(first.offload_timeouts_total, 4);
    assert_eq!(first.offload_rejections_total, 2);
    assert_eq!(
        first.worker_metric_resets_total, 0,
        "a first observation is not a generation boundary"
    );

    let rendered = handle.render();
    assert_eq!(
        exposition_value(&rendered, OwnerMetric::WorkerMemoryBytes.prometheus_name()),
        Some(987_654_321.0),
        "Prometheus exposition must carry the routed gauge value:\n{}",
        relevant_lines(&rendered)
    );
    assert_eq!(
        exposition_value(
            &rendered,
            OwnerMetric::BodyBufferingBytesTotal.prometheus_name()
        ),
        Some(8_675_309.0),
        "Prometheus exposition must carry the routed counter value:\n{}",
        relevant_lines(&rendered)
    );
    assert_eq!(
        exposition_type(&rendered, OwnerMetric::WorkerMemoryBytes.prometheus_name()).as_deref(),
        Some("gauge")
    );
    assert_eq!(
        exposition_type(
            &rendered,
            OwnerMetric::BodyBufferingBytesTotal.prometheus_name()
        )
        .as_deref(),
        Some("counter")
    );

    // Second refresh proves supervisor-lifetime counter truth survives the
    // poll and the generation identity is stable.
    let mut second_payload = payload.clone();
    second_payload.body_buffering_bytes_total += 1_024;
    let expected_counter = second_payload.body_buffering_bytes_total;
    conn.heartbeat(worker, second_payload).await;
    await_until("the second routed heartbeat to be stored", || {
        pm.get_unified_server_worker_metrics(worker)
            .is_some_and(|m| m.body_buffering_bytes_total == expected_counter)
    })
    .await;

    let second = aggregator.refresh(&pm, &handle);
    assert_eq!(
        second.worker_metric_resets_total, 0,
        "no generation boundary was crossed"
    );
    assert_eq!(
        second.body_buffering_bytes_total, expected_counter,
        "same-generation counter truth must accumulate monotonically"
    );
    assert_eq!(second.active_connections, 23);
    assert_eq!(
        exposition_value(
            &handle.render(),
            OwnerMetric::BodyBufferingBytesTotal.prometheus_name()
        ),
        Some(expected_counter as f64)
    );
}

/// Extract the single unlabelled sample value for `name` from a Prometheus
/// exposition payload.
fn exposition_value(payload: &str, name: &str) -> Option<f64> {
    payload.lines().find_map(|line| {
        let mut parts = line.split_whitespace();
        let key = parts.next()?;
        let value: f64 = parts.next()?.parse().ok()?;
        (key == name).then_some(value)
    })
}

fn exposition_type(payload: &str, name: &str) -> Option<String> {
    let prefix = format!("# TYPE {name} ");
    payload
        .lines()
        .find_map(|line| line.strip_prefix(&prefix).map(|kind| kind.to_string()))
}

fn relevant_lines(payload: &str) -> String {
    payload
        .lines()
        .filter(|l| l.contains("synvoid_subject_"))
        .collect::<Vec<_>>()
        .join("\n")
}
