//! Eggbench Security Qualification M003 telemetry bridge.
//!
//! This module owns the supervisor-side subject telemetry aggregation for
//! the `synvoid.eggbench-telemetry.v2` contract. It bridges heartbeat
//! snapshots from `ProcessManager` into a bounded set of stable Prometheus
//! metrics, preserves supervisor-lifetime counter monotonicity across
//! worker generations, and owns the loopback exporter lifecycle through
//! `SupervisorTaskRegistry`.
//!
//! # Why this exists
//!
//! Eggbench Security Qualification M003 (cross-repo, external) needs a
//! stable, versioned set of SynVoid-owned Prometheus metrics it can
//! scrape during security-performance trials. SynVoid is multi-process:
//! HTTP data-plane telemetry is produced in `UnifiedServerWorker`
//! processes and delivered via `WorkerMetricsPayload` heartbeats; CPU
//! offload telemetry is produced in the CPU worker and delivered via
//! `CpuOffloadStats` heartbeats. A supervisor-local metrics recorder
//! alone cannot observe child-process metrics, so this module is the
//! composition-boundary owner that pulls both heartbeat snapshots into
//! a single bridge.
//!
//! # Owner boundary
//!
//! The Prometheus listener for this contract is owned by the
//! supervisor/root composition layer because that layer owns
//! `ProcessManager` and therefore has authoritative cross-process
//! heartbeat snapshots. Per the plan, no `synvoid-metrics -> synvoid-ipc`
//! dependency cycle is introduced: this module lives at the root
//! composition boundary where `ProcessManager` is already available.
//!
//! # What this module does *not* do
//!
//! - It does not change worker heartbeat cadence.
//! - It does not lower any security limit or alter WAF semantics.
//! - It does not export per-worker / per-site / per-request labels —
//!   the v2 contract is bounded to aggregate / no-label inventory.
//! - It does not push authority into `synvoid-config` or
//!   `synvoid-config-model`. The runtime decides whether the exporter is
//!   enabled; the materializer-driven config provides the loopback port.
//!
//! See `plans/eggbench_security_qualification_m003_telemetry_interop_corrective.md`
//! for the binding corrective design. The v1 contract
//! (`synvoid.eggbench-telemetry.v1`) is withdrawn/unqualified historical
//! evidence; v2 is the sole current terminal authority.

use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use metrics_024::{counter as counter_macro, gauge as gauge_macro};
use metrics_exporter_prometheus::{PrometheusBuilder, PrometheusHandle, PrometheusRecorder};
use synvoid_ipc::{
    CpuOffloadStats, ProcessManager, UnifiedServerWorkerTelemetrySnapshot, WorkerId,
    WorkerMetricsPayload,
};

/// Owner contract identifier (immutable; any incompatible owner metric
/// change requires a new identifier). v2 advances from the withdrawn v1
/// because the corrective fixes a declared unit (`body_buffering_bytes_total`
/// `events` -> `bytes`, offload/reset counters `events` -> `count`) and
/// clarifies source-aggregation vs trial-aggregation semantics.
pub const CONTRACT_ID: &str = "synvoid.eggbench-telemetry.v2";
/// Owner contract JSON schema identifier.
pub const CONTRACT_SCHEMA_VERSION: &str = "synvoid.eggbench-telemetry.contract.v2";
/// Source refresh cadence is the documented Unified Server heartbeat
/// cadence. M003 telemetry is diagnostic initially; this value is part
/// of the contract and must match the live worker heartbeat cadence.
pub const SOURCE_REFRESH_CADENCE_SECS: u64 = 5;
/// The canonical loopback scrape URL (port is supplied by configuration
/// or materializer; the URL form is part of the contract).
pub const SCRAPE_PATH: &str = "/metrics";
/// Maximum number of worker generations retained in the bounded
/// monotonic counter bridge. Production pruning keeps bridge state bounded
/// by live `ProcessManager` worker state (see `BridgeState::prune_to_live`);
/// no arbitrary historical generation FIFO is retained.
#[allow(dead_code)]
const MAX_GENERATION_RETENTION: usize = 64;

/// Gauge vs counter classification. The exporter crate infers the
/// `TYPE` from the first sample registered for a metric.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OwnerMetricKind {
    Gauge,
    Counter,
}

impl OwnerMetricKind {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Gauge => "gauge",
            Self::Counter => "counter",
        }
    }
}

/// Owner metric inventory: every metric shipped under
/// `synvoid.eggbench-telemetry.v2`. Names are underscore-only so
/// Prometheus name sanitization does not become part of the
/// compatibility contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum OwnerMetric {
    EventLoopLagMs,
    RequestQueueP95Ms,
    ActiveConnections,
    WorkerMemoryBytes,
    WorkerCpuPercent,
    BodyBufferingBytesTotal,
    OffloadSubmissionsTotal,
    OffloadTimeoutsTotal,
    OffloadRejectionsTotal,
    OffloadFallbacksTotal,
    CpuWorkerRssBytes,
    WorkerMetricResetsTotal,
}

impl OwnerMetric {
    /// Exact Prometheus name as shipped under `synvoid.eggbench-telemetry.v2`.
    /// Names are part of the compatibility contract; rename = new owner
    /// contract version. v2 preserves the v1 sample names verbatim to
    /// reduce downstream churn; only units and aggregation semantics are
    /// corrected.
    pub const fn prometheus_name(self) -> &'static str {
        match self {
            Self::EventLoopLagMs => "synvoid_subject_event_loop_lag_ms",
            Self::RequestQueueP95Ms => "synvoid_subject_request_queue_p95_ms",
            Self::ActiveConnections => "synvoid_subject_active_connections",
            Self::WorkerMemoryBytes => "synvoid_subject_worker_memory_bytes",
            Self::WorkerCpuPercent => "synvoid_subject_worker_cpu_percent",
            Self::BodyBufferingBytesTotal => "synvoid_subject_body_buffering_bytes_total",
            Self::OffloadSubmissionsTotal => "synvoid_subject_offload_submissions_total",
            Self::OffloadTimeoutsTotal => "synvoid_subject_offload_timeouts_total",
            Self::OffloadRejectionsTotal => "synvoid_subject_offload_rejections_total",
            Self::OffloadFallbacksTotal => "synvoid_subject_offload_fallbacks_total",
            Self::CpuWorkerRssBytes => "synvoid_subject_cpu_worker_rss_bytes",
            Self::WorkerMetricResetsTotal => "synvoid_subject_worker_metric_resets_total",
        }
    }

    /// Kind: gauge or counter.
    pub const fn kind(self) -> OwnerMetricKind {
        match self {
            Self::EventLoopLagMs
            | Self::RequestQueueP95Ms
            | Self::ActiveConnections
            | Self::WorkerMemoryBytes
            | Self::WorkerCpuPercent
            | Self::CpuWorkerRssBytes => OwnerMetricKind::Gauge,
            Self::BodyBufferingBytesTotal
            | Self::OffloadSubmissionsTotal
            | Self::OffloadTimeoutsTotal
            | Self::OffloadRejectionsTotal
            | Self::OffloadFallbacksTotal
            | Self::WorkerMetricResetsTotal => OwnerMetricKind::Counter,
        }
    }

    /// Unit (the exporter crate does not emit `UNIT` metadata in 0.18.3,
    /// but the unit string is part of the owner contract and the
    /// manifest records it). v2 corrects the v1 unit defect:
    /// `body_buffering_bytes_total` is `bytes` (not generic `events`);
    /// offload/reset counters are `count`.
    pub const fn unit(self) -> &'static str {
        match self {
            Self::EventLoopLagMs => "ms",
            Self::RequestQueueP95Ms => "ms",
            Self::ActiveConnections => "connections",
            Self::WorkerMemoryBytes => "bytes",
            Self::WorkerCpuPercent => "percent",
            Self::CpuWorkerRssBytes => "bytes",
            Self::BodyBufferingBytesTotal => "bytes",
            Self::OffloadSubmissionsTotal
            | Self::OffloadTimeoutsTotal
            | Self::OffloadRejectionsTotal
            | Self::OffloadFallbacksTotal
            | Self::WorkerMetricResetsTotal => "count",
        }
    }

    /// Required vs optional under v2. CPU-worker RSS is optional because
    /// the supported minimal runtime may run without a CPU worker.
    /// The resets/boundary counter is optional because it is zero until
    /// the first generation boundary is observed.
    pub const fn required(self) -> bool {
        !matches!(
            self,
            Self::CpuWorkerRssBytes | Self::WorkerMetricResetsTotal
        )
    }

    /// Static owner/source aggregation rule (supervisor-side, across worker
    /// heartbeat snapshots at one instant). This is intentionally distinct
    /// from Eggbench trial aggregation (`mean|max|min` for gauges, none
    /// for counters) which Eggbench performs across repeated scrapes. A
    /// producer-side `sum` must never be placed in the trial-aggregation
    /// field.
    pub const fn source_aggregation(self) -> &'static str {
        match self {
            Self::EventLoopLagMs => "max",
            Self::RequestQueueP95Ms => "max",
            Self::ActiveConnections => "sum",
            Self::WorkerMemoryBytes => "sum",
            Self::WorkerCpuPercent => "sum",
            Self::BodyBufferingBytesTotal
            | Self::OffloadSubmissionsTotal
            | Self::OffloadTimeoutsTotal
            | Self::OffloadRejectionsTotal
            | Self::OffloadFallbacksTotal => "supervisor_lifetime_monotonic_bridge",
            Self::CpuWorkerRssBytes => "latest_ready",
            Self::WorkerMetricResetsTotal => "supervisor_lifetime_monotonic_bridge",
        }
    }

    /// Eggbench trial aggregation for `telemetry-mapping.json` (performed
    /// by Eggbench across repeated scrapes during a measured trial).
    /// Gauges use `mean|max|min`; counters use none (`None`). This is
    /// intentionally distinct from `source_aggregation`: e.g. active
    /// connections are source-summed across workers at one instant but
    /// trial-maxed across scrapes.
    pub const fn trial_aggregation(self) -> Option<&'static str> {
        match self {
            Self::EventLoopLagMs => Some("max"),
            Self::RequestQueueP95Ms => Some("max"),
            Self::ActiveConnections => Some("max"),
            Self::WorkerMemoryBytes => Some("max"),
            Self::WorkerCpuPercent => Some("mean"),
            Self::CpuWorkerRssBytes => Some("max"),
            Self::BodyBufferingBytesTotal
            | Self::OffloadSubmissionsTotal
            | Self::OffloadTimeoutsTotal
            | Self::OffloadRejectionsTotal
            | Self::OffloadFallbacksTotal
            | Self::WorkerMetricResetsTotal => None,
        }
    }

    /// Source field on the worker payload / CPU-worker snapshot.
    pub const fn source_field(self) -> &'static str {
        match self {
            Self::EventLoopLagMs => "WorkerMetricsPayload::event_loop_lag_ms",
            Self::RequestQueueP95Ms => "WorkerMetricsPayload::request_queue_time_ms.p95_ms",
            Self::ActiveConnections => "WorkerMetricsPayload::active_connections",
            Self::WorkerMemoryBytes => "WorkerMetricsPayload::memory_bytes",
            Self::WorkerCpuPercent => "WorkerMetricsPayload::cpu_percent",
            Self::BodyBufferingBytesTotal => "WorkerMetricsPayload::body_buffering_bytes_total",
            Self::OffloadSubmissionsTotal => "WorkerMetricsPayload::offload_submissions_total",
            Self::OffloadTimeoutsTotal => "WorkerMetricsPayload::offload_timeouts_total",
            Self::OffloadRejectionsTotal => "WorkerMetricsPayload::offload_rejections_total",
            Self::OffloadFallbacksTotal => "WorkerMetricsPayload::offload_fallbacks_total",
            Self::CpuWorkerRssBytes => "CpuOffloadStats::worker_rss_bytes",
            Self::WorkerMetricResetsTotal => "internal_counter",
        }
    }

    /// Restart/reset semantics. Counters are bridged monotonic; absent
    /// optional sources are omitted.
    pub const fn reset_semantics(self) -> &'static str {
        match self {
            Self::EventLoopLagMs
            | Self::RequestQueueP95Ms
            | Self::ActiveConnections
            | Self::WorkerMemoryBytes
            | Self::WorkerCpuPercent => "latest_value_per_worker_snapshot",
            Self::BodyBufferingBytesTotal
            | Self::OffloadSubmissionsTotal
            | Self::OffloadTimeoutsTotal
            | Self::OffloadRejectionsTotal
            | Self::OffloadFallbacksTotal
            | Self::WorkerMetricResetsTotal => {
                "supervisor_lifetime_monotonic_with_reset_boundary_observation"
            }
            Self::CpuWorkerRssBytes => "omitted_when_cpu_worker_absent",
        }
    }

    /// HELP text for the metric; emitted via the recorder's metadata
    /// when the metric is first published.
    pub const fn help(self) -> &'static str {
        match self {
            Self::EventLoopLagMs => "Maximum event_loop_lag_ms across Unified Server workers (ms).",
            Self::RequestQueueP95Ms => {
                "Maximum p95 request_queue_time_ms across Unified Server workers (ms)."
            }
            Self::ActiveConnections => "Sum of active_connections across Unified Server workers.",
            Self::WorkerMemoryBytes => "Sum of memory_bytes across Unified Server workers.",
            Self::WorkerCpuPercent => "Sum of cpu_percent across Unified Server workers.",
            Self::BodyBufferingBytesTotal => {
                "Supervisor-lifetime monotonic bridge of body_buffering_bytes_total."
            }
            Self::OffloadSubmissionsTotal => {
                "Supervisor-lifetime monotonic bridge of offload_submissions_total."
            }
            Self::OffloadTimeoutsTotal => {
                "Supervisor-lifetime monotonic bridge of offload_timeouts_total."
            }
            Self::OffloadRejectionsTotal => {
                "Supervisor-lifetime monotonic bridge of offload_rejections_total."
            }
            Self::OffloadFallbacksTotal => {
                "Supervisor-lifetime monotonic bridge of offload_fallbacks_total."
            }
            Self::CpuWorkerRssBytes => "Latest ready CPU-worker worker_rss_bytes (bytes).",
            Self::WorkerMetricResetsTotal => {
                "Total worker counter reset boundaries observed during bridging."
            }
        }
    }

    /// Source field the monotonic bridge reads from a worker payload.
    fn worker_counter_value(self, payload: &WorkerMetricsPayload) -> u64 {
        match self {
            Self::BodyBufferingBytesTotal => payload.body_buffering_bytes_total,
            Self::OffloadSubmissionsTotal => payload.offload_submissions_total,
            Self::OffloadTimeoutsTotal => payload.offload_timeouts_total,
            Self::OffloadRejectionsTotal => payload.offload_rejections_total,
            Self::OffloadFallbacksTotal => payload.offload_fallbacks_total,
            _ => 0,
        }
    }
}

/// Static owner inventory in stable declaration order. The manifest and
/// `telemetry-mapping.json` emit this order; tests pin it.
pub const OWNER_INVENTORY: &[OwnerMetric] = &[
    OwnerMetric::EventLoopLagMs,
    OwnerMetric::RequestQueueP95Ms,
    OwnerMetric::ActiveConnections,
    OwnerMetric::WorkerMemoryBytes,
    OwnerMetric::WorkerCpuPercent,
    OwnerMetric::BodyBufferingBytesTotal,
    OwnerMetric::OffloadSubmissionsTotal,
    OwnerMetric::OffloadTimeoutsTotal,
    OwnerMetric::OffloadRejectionsTotal,
    OwnerMetric::OffloadFallbacksTotal,
    OwnerMetric::CpuWorkerRssBytes,
    OwnerMetric::WorkerMetricResetsTotal,
];

/// Per-worker counter monotonicity state. Worker payloads carry
/// process-lifetime absolute counters; summing current worker snapshots
/// can decrease after a worker restart. We retain the supervisor-observed
/// generation plus the last-seen absolute per counter, and observe
/// generation/reset boundaries explicitly rather than inferring them from
/// counter magnitude.
#[derive(Debug, Clone, Default)]
struct WorkerCounterState {
    /// Supervisor-observed generation for this worker ID.
    generation: u64,
    /// Last observed absolute value per bridged counter.
    last_absolute: HashMap<OwnerMetric, u64>,
}

/// Typed counter-observation vocabulary (corrective v2). First observation
/// and reset/generation change are distinct states: a first nonzero
/// observation seeds cumulative truth and is never counted as a reset.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CounterObservation {
    /// First observation for this worker ID: seeds cumulative truth.
    First(u64),
    /// Same-generation increase: contributes `current - previous`.
    Delta(u64),
    /// Explicit generation change: re-baselines, contributes new absolute.
    GenerationReset(u64),
    /// Unexpected same-generation decrease: re-baselines without a
    /// negative delta, contributes new absolute, observable once per
    /// worker observation.
    CounterReset(u64),
    /// Unchanged: contributes zero.
    Unchanged,
}

fn observe_counter(
    previous: Option<u64>,
    current: u64,
    generation_changed: bool,
) -> CounterObservation {
    match previous {
        None => CounterObservation::First(current),
        Some(prev) => {
            if generation_changed {
                CounterObservation::GenerationReset(current)
            } else if current == prev {
                CounterObservation::Unchanged
            } else if current > prev {
                CounterObservation::Delta(current - prev)
            } else {
                CounterObservation::CounterReset(current)
            }
        }
    }
}

/// Bridge state: per-worker counter monotonicity plus running
/// supervisor-lifetime cumulative counter values. Owned by the bridge
/// task; not accessed concurrently.
///
/// `worker_metric_resets_total` (v2 semantics): counts worker
/// generation-boundary + unexpected same-generation decrease events,
/// exactly once per worker observation that contains such a boundary —
/// never once per counter, never for first observations.
#[derive(Debug, Default)]
struct BridgeState {
    worker_counter_state: HashMap<WorkerId, WorkerCounterState>,
    /// Supervisor-lifetime cumulative counter truth. Each poll contributes
    /// only per-worker deltas; the snapshot publishes these cumulative
    /// values via absolute counter semantics so exposition never decreases.
    cumulative: CounterDeltas,
    /// Total generation/reset boundaries observed (v2 meaning above).
    total_resets: u64,
}

impl BridgeState {
    /// Generation-aware per-worker application (corrective v2).
    ///
    /// - first observation seeds cumulative with the current absolute and
    ///   does not increment `total_resets`;
    /// - same-generation increase contributes `current - previous`;
    /// - explicit generation change re-baselines all bridged counters,
    ///   contributes new absolutes, increments `total_resets` once;
    /// - unexpected same-generation decrease re-baselines without a
    ///   negative delta and increments `total_resets` once per worker
    ///   observation (not once per counter);
    /// - unchanged contributes zero; arithmetic is saturating.
    fn apply_worker(
        &mut self,
        id: WorkerId,
        generation: u64,
        payload: &WorkerMetricsPayload,
    ) -> CounterDeltas {
        const BRIDGED: &[OwnerMetric] = &[
            OwnerMetric::BodyBufferingBytesTotal,
            OwnerMetric::OffloadSubmissionsTotal,
            OwnerMetric::OffloadTimeoutsTotal,
            OwnerMetric::OffloadRejectionsTotal,
            OwnerMetric::OffloadFallbacksTotal,
        ];
        let generation = generation.max(1);
        let is_first = !self.worker_counter_state.contains_key(&id);
        let stored_generation = self
            .worker_counter_state
            .get(&id)
            .map(|s| s.generation)
            .unwrap_or(0);
        let generation_changed = !is_first && stored_generation != generation;

        let state = self
            .worker_counter_state
            .entry(id)
            .or_insert_with(WorkerCounterState::default);
        // Record the observed generation before computing observations so
        // a new worker ID seeds generation truth immediately.
        if is_first {
            state.generation = generation;
        }

        let mut deltas = CounterDeltas::default();
        let mut worker_boundary = false;
        for &metric in BRIDGED {
            let current = metric.worker_counter_value(payload);
            let previous = if is_first {
                None
            } else {
                state.last_absolute.get(&metric).copied()
            };
            let observation = observe_counter(previous, current, generation_changed);
            let delta = match observation {
                CounterObservation::First(v)
                | CounterObservation::Delta(v)
                | CounterObservation::GenerationReset(v)
                | CounterObservation::CounterReset(v) => v,
                CounterObservation::Unchanged => 0,
            };
            // Boundary accounting: generation change or unexpected
            // same-generation decrease. First observations never count.
            // Count once per worker observation (see below), not here.
            match observation {
                CounterObservation::GenerationReset(_) | CounterObservation::CounterReset(_) => {
                    worker_boundary = true;
                }
                CounterObservation::First(_)
                | CounterObservation::Delta(_)
                | CounterObservation::Unchanged => {}
            }
            state.last_absolute.insert(metric, current);
            match metric {
                OwnerMetric::BodyBufferingBytesTotal => {
                    deltas.body_buffering_bytes = delta;
                }
                OwnerMetric::OffloadSubmissionsTotal => {
                    deltas.offload_submissions = delta;
                }
                OwnerMetric::OffloadTimeoutsTotal => {
                    deltas.offload_timeouts = delta;
                }
                OwnerMetric::OffloadRejectionsTotal => {
                    deltas.offload_rejections = delta;
                }
                OwnerMetric::OffloadFallbacksTotal => {
                    deltas.offload_fallbacks = delta;
                }
                _ => {}
            }
        }
        if generation_changed {
            state.generation = generation;
        }
        if worker_boundary {
            self.total_resets = self.total_resets.saturating_add(1);
        }
        // Accumulate into supervisor-lifetime truth (saturating).
        self.cumulative.body_buffering_bytes = self
            .cumulative
            .body_buffering_bytes
            .saturating_add(deltas.body_buffering_bytes);
        self.cumulative.offload_submissions = self
            .cumulative
            .offload_submissions
            .saturating_add(deltas.offload_submissions);
        self.cumulative.offload_timeouts = self
            .cumulative
            .offload_timeouts
            .saturating_add(deltas.offload_timeouts);
        self.cumulative.offload_rejections = self
            .cumulative
            .offload_rejections
            .saturating_add(deltas.offload_rejections);
        self.cumulative.offload_fallbacks = self
            .cumulative
            .offload_fallbacks
            .saturating_add(deltas.offload_fallbacks);
        deltas
    }

    /// Production pruning (corrective v2): retain bridge state only for
    /// worker IDs present in the authoritative `ProcessManager` snapshot.
    /// Called on every bridge refresh so retained state is bounded by live
    /// worker state with no historical FIFO.
    fn prune_to_live(&mut self, live_ids: &HashSet<WorkerId>) {
        self.worker_counter_state
            .retain(|id, _| live_ids.contains(id));
    }

    /// Backwards-compatible single-ID retirement (tests + transitional
    /// callers). Production code uses `prune_to_live`.
    #[allow(dead_code)]
    fn retire(&mut self, id: WorkerId) {
        self.worker_counter_state.remove(&id);
    }
}

#[derive(Debug, Default, Clone, Copy)]
struct CounterDeltas {
    body_buffering_bytes: u64,
    offload_submissions: u64,
    offload_timeouts: u64,
    offload_rejections: u64,
    offload_fallbacks: u64,
}

/// Aggregator: pure function from worker payloads + CPU-worker snapshot
/// to the bridge's current Prometheus-emittable snapshot. The bridge
/// task uses it; tests use it directly.
#[derive(Debug, Clone, Default)]
pub struct BridgeSnapshot {
    /// Max event_loop_lag_ms across Unified Server workers; zero if no
    /// workers. The metric is only emitted when at least one worker
    /// heartbeat has been observed, so a value of zero is real.
    pub event_loop_lag_ms: u64,
    /// Max p95 request queue time across Unified Server workers.
    pub request_queue_p95_ms: u64,
    pub active_connections: u64,
    pub worker_memory_bytes: u64,
    pub worker_cpu_percent: f64,
    pub body_buffering_bytes_total: u64,
    pub offload_submissions_total: u64,
    pub offload_timeouts_total: u64,
    pub offload_rejections_total: u64,
    pub offload_fallbacks_total: u64,
    pub cpu_worker_rss_bytes: Option<u64>,
    pub worker_metric_resets_total: u64,
}

impl BridgeSnapshot {
    /// Aggregate gauge snapshots from a list of worker payloads. Empty
    /// input leaves all gauges at zero; the bridge decides whether to
    /// publish them at all.
    pub fn from_worker_gauges(workers: &[(WorkerId, WorkerMetricsPayload)]) -> Self {
        let mut s = Self::default();
        let mut saw_worker = false;
        for (_id, payload) in workers {
            saw_worker = true;
            s.event_loop_lag_ms = s.event_loop_lag_ms.max(payload.event_loop_lag_ms);
            s.request_queue_p95_ms = s
                .request_queue_p95_ms
                .max(payload.request_queue_time_ms.p95_ms as u64);
            s.active_connections = s
                .active_connections
                .saturating_add(payload.active_connections);
            s.worker_memory_bytes = s.worker_memory_bytes.saturating_add(payload.memory_bytes);
            s.worker_cpu_percent += payload.cpu_percent;
        }
        if !saw_worker {
            s.event_loop_lag_ms = 0;
            s.request_queue_p95_ms = 0;
            s.active_connections = 0;
            s.worker_memory_bytes = 0;
            s.worker_cpu_percent = 0.0;
        }
        s
    }

    /// Merge the latest CPU-worker snapshot (only when CPU worker is
    /// ready; never fabricate zero).
    pub fn apply_cpu_worker(&mut self, cpu: Option<&CpuOffloadStats>) {
        self.cpu_worker_rss_bytes = cpu.map(|s| s.worker_rss_bytes);
    }
}

/// Outcome of an attempt to install the recorder and start the exporter.
#[derive(Debug)]
pub enum TelemetryStartError {
    InvalidAddress(String),
    BuildFailed(String),
    AlreadyInstalled,
}

/// Build a `PrometheusBuilder` configured for the loopback exporter
/// and install the recorder globally exactly once. The exporter
/// future itself is returned (not spawned); the caller (typically the
/// supervisor's `SupervisorTaskRegistry`) owns the `JoinHandle` so
/// shutdown is observable.
///
/// Caller must already be inside an active Tokio runtime.
pub fn install_recorder_and_exporter(
    bind_addr: SocketAddr,
) -> std::result::Result<
    (
        PrometheusHandle,
        metrics_exporter_prometheus::ExporterFuture,
    ),
    TelemetryStartError,
> {
    // 1. Build the recorder + exporter pair. PrometheusBuilder::build()
    //    requires a Tokio runtime context.
    let (recorder, exporter) = PrometheusBuilder::new()
        .with_http_listener(bind_addr)
        .build()
        .map_err(|e| TelemetryStartError::BuildFailed(e.to_string()))?;

    // 2. Acquire the handle before installing the recorder; the
    //    handle is the clonable, renderable view onto the recorder
    //    state, while `PrometheusRecorder` itself is not Clone.
    let handle = recorder.handle();

    // 3. Install the recorder globally. The exporter crate's
    //    `install()`/`install_recorder()` would also do this for us,
    //    but we install explicitly so that the supervisor-side bridge
    //    is the single, visible install path. The
    //    `AlreadyInstalled` branch is the only failure mode of
    //    `set_global_recorder`.
    install_recorder(recorder)?;

    Ok((handle, exporter))
}

/// Backwards-compatible spawn helper kept for callers that don't need
/// explicit JoinHandle ownership. The exporter future is registered
/// with the supervisor's task registry by the supervisor itself;
/// this helper returns the future so the caller can spawn it under a
/// known context. Used by `tests/`.
#[allow(dead_code)]
fn _retained_compat_marker() {}

/// Install a built recorder globally exactly once. Surfaces
/// `metrics_024::set_global_recorder`'s already-installed error as
/// `TelemetryStartError::AlreadyInstalled`.
pub fn install_recorder(recorder: PrometheusRecorder) -> Result<(), TelemetryStartError> {
    if metrics_024::set_global_recorder(recorder).is_err() {
        // The metrics 0.24 `SetRecorderError` is a struct that always
        // indicates "already installed" — see
        // metrics-0.24.6/src/recorder/cell.rs `set`. Surface it
        // uniformly.
        return Err(TelemetryStartError::AlreadyInstalled);
    }
    Ok(())
}

/// Walk the owner inventory and confirm every metric is registered with
/// the supplied handle. The exporter crate infers TYPE/HELP from the
/// first sample; this function pre-seeds all counters at zero so the
/// exposition payload always carries a stable metric set, even when no
/// worker heartbeat has been observed yet.
pub fn register_inventory(handle: &PrometheusHandle) {
    // Pre-seed counters at zero (counters must have at least one sample
    // for TYPE/HELP to be emitted).
    for &metric in OWNER_INVENTORY {
        if metric.kind() == OwnerMetricKind::Counter {
            counter_macro!(metric.prometheus_name()).absolute(0);
        }
    }
    // Touch the handle so the recorder link is not dropped at compile
    // time when metrics:: macros are static-initialised.
    let _ = handle.render();
}

/// Bounded monotonic aggregation state for the v2 bridge.
///
/// The cadence loop (`run_telemetry_bridge_loop`) owns one of these for the
/// supervisor's lifetime, but the refresh itself is a deterministic function
/// of `(ProcessManager, PrometheusHandle)`. Owning the state here lets
/// composition proofs drive the exact production aggregation path — dispatch
/// -> `ProcessManager` -> generation-aware snapshot -> Prometheus — without
/// waiting on the 5s cadence and without a second, divergent copy of the
/// aggregation rules.
#[derive(Debug, Default)]
pub struct BridgeAggregator {
    state: BridgeState,
}

impl BridgeAggregator {
    pub fn new() -> Self {
        Self {
            state: BridgeState::default(),
        }
    }

    /// One bridge refresh tick. Pulls the generation-aware authoritative
    /// snapshot, prunes bridge state to live workers, folds per-worker
    /// counters into supervisor-lifetime monotonic truth, and publishes the
    /// resulting Prometheus snapshot. Returns the published snapshot.
    pub fn refresh(&mut self, pm: &ProcessManager, handle: &PrometheusHandle) -> BridgeSnapshot {
        // Generation-aware authoritative snapshot: explicit worker generation
        // identity from ProcessManager, never inferred from counter magnitude
        // (corrective v2).
        let snapshots: Vec<UnifiedServerWorkerTelemetrySnapshot> =
            pm.get_all_unified_server_worker_metrics_with_generation();
        let cpu = if pm.is_cpu_worker_ready() {
            Some(pm.get_cpu_worker_cpu_offload_stats())
        } else {
            None
        };

        // Production pruning: bound bridge state by live ProcessManager
        // worker state on every refresh (corrective v2 §7).
        let live_ids: HashSet<WorkerId> = snapshots.iter().map(|s| s.worker_id).collect();
        self.state.prune_to_live(&live_ids);

        let gauge_inputs: Vec<(WorkerId, WorkerMetricsPayload)> = snapshots
            .iter()
            .map(|s| (s.worker_id, s.metrics.clone()))
            .collect();
        let mut snapshot = BridgeSnapshot::from_worker_gauges(&gauge_inputs);
        snapshot.apply_cpu_worker(cpu.as_ref());

        // Counter monotonicity: per-worker deltas accumulate into
        // supervisor-lifetime cumulative truth inside BridgeState.
        for s in &snapshots {
            self.state
                .apply_worker(s.worker_id, s.generation, &s.metrics);
        }
        snapshot.body_buffering_bytes_total = self.state.cumulative.body_buffering_bytes;
        snapshot.offload_submissions_total = self.state.cumulative.offload_submissions;
        snapshot.offload_timeouts_total = self.state.cumulative.offload_timeouts;
        snapshot.offload_rejections_total = self.state.cumulative.offload_rejections;
        snapshot.offload_fallbacks_total = self.state.cumulative.offload_fallbacks;
        snapshot.worker_metric_resets_total = self.state.total_resets;

        publish_snapshot(handle, &snapshot);
        snapshot
    }
}

/// Bridge loop entry point. Designed to be spawned by the supervisor
/// (which owns the JoinHandle and registers it with
/// `SupervisorTaskRegistry`). The future returns `()` on shutdown and
/// is intentionally not instrumented for task-registry outcome
/// classification — it is a maintenance task that simply exits on the
/// shutdown signal.
pub async fn run_telemetry_bridge_loop(
    pm: Arc<ProcessManager>,
    handle: PrometheusHandle,
    snapshot_lock: Arc<parking_lot::RwLock<BridgeSnapshot>>,
    alive: Arc<std::sync::atomic::AtomicBool>,
    mut shutdown_rx: tokio::sync::broadcast::Receiver<()>,
) {
    let mut aggregator = BridgeAggregator::new();
    let mut ticker = tokio::time::interval(Duration::from_secs(SOURCE_REFRESH_CADENCE_SECS));
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    let _ = ticker.tick().await;

    loop {
        tokio::select! {
            _ = shutdown_rx.recv() => break,
            _ = ticker.tick() => {}
        }

        let snapshot = aggregator.refresh(&pm, &handle);
        *snapshot_lock.write() = snapshot;
    }

    alive.store(false, std::sync::atomic::Ordering::Release);
}

/// Bridge spawn entry point: install recorder + exporter pair, build
/// the bridge state, and return the pieces the supervisor needs to
/// register with `SupervisorTaskRegistry`. The supervisor owns the
/// JoinHandles; the bridge itself never spawns.
pub fn start_telemetry_bridge(
    bind_addr: SocketAddr,
    pm: Arc<ProcessManager>,
) -> std::result::Result<TelemetryBridgeParts, TelemetryStartError> {
    let (handle, exporter_future) = install_recorder_and_exporter(bind_addr)?;
    register_inventory(&handle);

    let snapshot_lock = Arc::new(parking_lot::RwLock::new(BridgeSnapshot::default()));
    let alive = Arc::new(std::sync::atomic::AtomicBool::new(true));

    let handle_for_loop = handle.clone();
    let snapshot_lock_for_loop = snapshot_lock.clone();
    let alive_for_loop = alive.clone();

    Ok(TelemetryBridgeParts {
        exporter_future,
        bridge_loop: Box::new(move |shutdown_rx| {
            Box::pin(run_telemetry_bridge_loop(
                pm,
                handle_for_loop,
                snapshot_lock_for_loop,
                alive_for_loop,
                shutdown_rx,
            ))
        }),
        handle: TelemetryHandle {
            handle,
            snapshot: snapshot_lock,
            alive,
        },
    })
}

/// Bridge loop factory: receives a shutdown receiver and returns a
/// pinned future that drives the periodic aggregation until the
/// receiver fires. The supervisor spawns this future under its own task
/// registry so its JoinHandle is observable during drain.
pub type BridgeLoopFactory = Box<
    dyn FnOnce(
            tokio::sync::broadcast::Receiver<()>,
        ) -> std::pin::Pin<Box<dyn std::future::Future<Output = ()> + Send>>
        + Send,
>;

/// Pieces returned by `start_telemetry_bridge` that the supervisor
/// spawns and registers with `SupervisorTaskRegistry`. The exporter
/// future is the loopback Prometheus listener; the bridge loop is the
/// periodic aggregation task. Both must be drained during supervisor
/// shutdown.
pub struct TelemetryBridgeParts {
    /// Loopback Prometheus exporter future.
    pub exporter_future: metrics_exporter_prometheus::ExporterFuture,
    /// Bridge loop factory; the supervisor calls this with its own
    /// shutdown receiver and registers the resulting JoinHandle.
    pub bridge_loop: BridgeLoopFactory,
    /// Handle returned for test/closeout introspection.
    pub handle: TelemetryHandle,
}

/// Handle returned by `start_telemetry_bridge`. The supervisor drains
/// the bridge via shutdown coordination; the bridge's registered
/// exporter task is joined by `SupervisorTaskRegistry::shutdown_and_join`
/// alongside the other supervisor tasks.
pub struct TelemetryHandle {
    handle: PrometheusHandle,
    /// Last known bridge snapshot. Useful for tests and the closeout
    /// evidence dump.
    pub snapshot: Arc<parking_lot::RwLock<BridgeSnapshot>>,
    /// Bridge still alive flag (set to false once the task returned).
    pub alive: Arc<std::sync::atomic::AtomicBool>,
}

impl TelemetryHandle {
    /// Acquire a rendered scrape payload. Bypasses the network listener
    /// so live proof tests can deterministically fetch exposition without
    /// a network round trip; the on-disk listener serves the same
    /// payload via the exporter's own request loop.
    pub fn render(&self) -> String {
        self.handle.render()
    }

    pub fn is_alive(&self) -> bool {
        self.alive.load(std::sync::atomic::Ordering::Acquire)
    }

    pub fn last_snapshot(&self) -> BridgeSnapshot {
        self.snapshot.read().clone()
    }
}

/// Publish the snapshot onto the recorder. Counters are absolute
/// values; gauges use the latest value semantics.
fn publish_snapshot(handle: &PrometheusHandle, snapshot: &BridgeSnapshot) {
    let _ = handle;
    gauge_macro!(OwnerMetric::EventLoopLagMs.prometheus_name())
        .set(snapshot.event_loop_lag_ms as f64);
    gauge_macro!(OwnerMetric::RequestQueueP95Ms.prometheus_name())
        .set(snapshot.request_queue_p95_ms as f64);
    gauge_macro!(OwnerMetric::ActiveConnections.prometheus_name())
        .set(snapshot.active_connections as f64);
    gauge_macro!(OwnerMetric::WorkerMemoryBytes.prometheus_name())
        .set(snapshot.worker_memory_bytes as f64);
    gauge_macro!(OwnerMetric::WorkerCpuPercent.prometheus_name()).set(snapshot.worker_cpu_percent);
    if let Some(rss) = snapshot.cpu_worker_rss_bytes {
        gauge_macro!(OwnerMetric::CpuWorkerRssBytes.prometheus_name()).set(rss as f64);
    }
    counter_macro!(OwnerMetric::BodyBufferingBytesTotal.prometheus_name())
        .absolute(snapshot.body_buffering_bytes_total);
    counter_macro!(OwnerMetric::OffloadSubmissionsTotal.prometheus_name())
        .absolute(snapshot.offload_submissions_total);
    counter_macro!(OwnerMetric::OffloadTimeoutsTotal.prometheus_name())
        .absolute(snapshot.offload_timeouts_total);
    counter_macro!(OwnerMetric::OffloadRejectionsTotal.prometheus_name())
        .absolute(snapshot.offload_rejections_total);
    counter_macro!(OwnerMetric::OffloadFallbacksTotal.prometheus_name())
        .absolute(snapshot.offload_fallbacks_total);
    counter_macro!(OwnerMetric::WorkerMetricResetsTotal.prometheus_name())
        .absolute(snapshot.worker_metric_resets_total);
}

#[cfg(test)]
mod tests {
    use super::*;

    fn empty_payload() -> WorkerMetricsPayload {
        WorkerMetricsPayload::default()
    }

    #[test]
    fn inventory_names_are_stable_and_underscore_only() {
        let names: Vec<&'static str> = OWNER_INVENTORY
            .iter()
            .map(|m| m.prometheus_name())
            .collect();
        // Pin order.
        assert_eq!(
            names,
            vec![
                "synvoid_subject_event_loop_lag_ms",
                "synvoid_subject_request_queue_p95_ms",
                "synvoid_subject_active_connections",
                "synvoid_subject_worker_memory_bytes",
                "synvoid_subject_worker_cpu_percent",
                "synvoid_subject_body_buffering_bytes_total",
                "synvoid_subject_offload_submissions_total",
                "synvoid_subject_offload_timeouts_total",
                "synvoid_subject_offload_rejections_total",
                "synvoid_subject_offload_fallbacks_total",
                "synvoid_subject_cpu_worker_rss_bytes",
                "synvoid_subject_worker_metric_resets_total",
            ]
        );
        for n in names {
            assert!(n.is_ascii(), "name {n:?} contains non-ASCII");
            assert!(n.starts_with("synvoid_subject_"));
            assert!(
                !n.contains('-'),
                "name {n:?} contains hyphen (sanitization risk)"
            );
        }
    }

    #[test]
    fn required_metrics_count_matches_v2_inventory() {
        let required = OWNER_INVENTORY.iter().filter(|m| m.required()).count();
        assert_eq!(
            required, 10,
            "10 required metrics in v2 (CPU-worker RSS + resets optional)"
        );
    }

    #[test]
    fn gauge_aggregation_max_for_lag_and_queue_p95() {
        let id1 = WorkerId(1);
        let id2 = WorkerId(2);
        let mut a = empty_payload();
        a.event_loop_lag_ms = 5;
        a.request_queue_time_ms.p95_ms = 10.0;
        let mut b = empty_payload();
        b.event_loop_lag_ms = 12;
        b.request_queue_time_ms.p95_ms = 7.0;
        let snap = BridgeSnapshot::from_worker_gauges(&[(id1, a), (id2, b)]);
        assert_eq!(snap.event_loop_lag_ms, 12);
        assert_eq!(snap.request_queue_p95_ms, 10);
    }

    #[test]
    fn gauge_aggregation_sum_for_active_connections_and_memory() {
        let id = WorkerId(1);
        let mut a = empty_payload();
        a.active_connections = 3;
        a.memory_bytes = 100;
        a.cpu_percent = 12.5;
        let mut b = empty_payload();
        b.active_connections = 7;
        b.memory_bytes = 200;
        b.cpu_percent = 7.5;
        let snap = BridgeSnapshot::from_worker_gauges(&[(id, a), (id, b)]);
        assert_eq!(snap.active_connections, 10);
        assert_eq!(snap.worker_memory_bytes, 300);
        assert_eq!(snap.worker_cpu_percent, 20.0);
    }

    #[test]
    fn absent_cpu_worker_does_not_fabricate_zero() {
        let mut snap = BridgeSnapshot::default();
        snap.apply_cpu_worker(None);
        assert_eq!(snap.cpu_worker_rss_bytes, None);
        let mut cpu = CpuOffloadStats::default();
        cpu.worker_rss_bytes = 4096;
        snap.apply_cpu_worker(Some(&cpu));
        assert_eq!(snap.cpu_worker_rss_bytes, Some(4096));
    }

    #[test]
    fn counter_first_nonzero_observation_is_not_a_reset_but_seeds_truth() {
        let id = WorkerId(1);
        let mut state = BridgeState::default();
        let mut payload = empty_payload();
        payload.body_buffering_bytes_total = 1000;
        payload.offload_submissions_total = 50;
        let deltas = state.apply_worker(id, 1, &payload);
        assert_eq!(deltas.body_buffering_bytes, 1000);
        assert_eq!(deltas.offload_submissions, 50);
        assert_eq!(
            state.total_resets, 0,
            "first nonzero observation must not count as a reset (v2 §6.1)"
        );
        assert_eq!(state.cumulative.body_buffering_bytes, 1000);
        assert_eq!(state.cumulative.offload_submissions, 50);
    }

    #[test]
    fn counter_same_generation_delta_is_exact() {
        let id = WorkerId(1);
        let mut state = BridgeState::default();
        let mut payload = empty_payload();
        payload.body_buffering_bytes_total = 1000;
        let _ = state.apply_worker(id, 1, &payload);

        payload.body_buffering_bytes_total = 1500;
        let deltas = state.apply_worker(id, 1, &payload);
        assert_eq!(deltas.body_buffering_bytes, 500);
        assert_eq!(state.total_resets, 0, "no new boundary on increase");
        assert_eq!(state.cumulative.body_buffering_bytes, 1500);
    }

    #[test]
    fn counter_unchanged_contributes_zero() {
        let id = WorkerId(1);
        let mut state = BridgeState::default();
        let mut payload = empty_payload();
        payload.body_buffering_bytes_total = 1000;
        let _ = state.apply_worker(id, 1, &payload);
        let deltas = state.apply_worker(id, 1, &payload);
        assert_eq!(deltas.body_buffering_bytes, 0);
        assert_eq!(state.total_resets, 0);
        assert_eq!(state.cumulative.body_buffering_bytes, 1000);
    }

    #[test]
    fn explicit_generation_change_lower_value_rebaselines_once() {
        let id = WorkerId(1);
        let mut state = BridgeState::default();
        let mut payload = empty_payload();
        payload.body_buffering_bytes_total = 1500;
        payload.offload_submissions_total = 300;
        payload.offload_timeouts_total = 20;
        payload.offload_rejections_total = 10;
        payload.offload_fallbacks_total = 5;
        let _ = state.apply_worker(id, 1, &payload);

        // Restarted process, generation 2, counters reset low.
        payload.body_buffering_bytes_total = 200;
        payload.offload_submissions_total = 30;
        payload.offload_timeouts_total = 2;
        payload.offload_rejections_total = 1;
        payload.offload_fallbacks_total = 0;
        let deltas = state.apply_worker(id, 2, &payload);
        assert_eq!(deltas.body_buffering_bytes, 200);
        assert_eq!(deltas.offload_submissions, 30);
        assert_eq!(
            state.total_resets, 1,
            "generation transition counts once, not once per metric"
        );
        assert_eq!(state.cumulative.body_buffering_bytes, 1700);
    }

    #[test]
    fn explicit_generation_change_higher_value_is_still_detected() {
        let id = WorkerId(1);
        let mut state = BridgeState::default();
        let mut payload = empty_payload();
        payload.body_buffering_bytes_total = 100;
        let _ = state.apply_worker(id, 1, &payload);

        // Restarted process already accumulated past the old value before
        // the next bridge poll: magnitude inference alone would miss this,
        // but explicit generation identity must detect it.
        payload.body_buffering_bytes_total = 5000;
        let deltas = state.apply_worker(id, 2, &payload);
        assert_eq!(deltas.body_buffering_bytes, 5000);
        assert_eq!(state.total_resets, 1);
        assert_eq!(state.cumulative.body_buffering_bytes, 5100);
    }

    #[test]
    fn unexpected_same_generation_decrease_never_emits_negative_delta() {
        let id = WorkerId(1);
        let mut state = BridgeState::default();
        let mut payload = empty_payload();
        payload.body_buffering_bytes_total = 1500;
        payload.offload_submissions_total = 100;
        let _ = state.apply_worker(id, 1, &payload);

        // Same generation, one counter decreases unexpectedly (no restart
        // signal). Re-baseline without negative delta; count once for the
        // worker observation.
        payload.body_buffering_bytes_total = 200;
        payload.offload_submissions_total = 120;
        let deltas = state.apply_worker(id, 1, &payload);
        assert_eq!(deltas.body_buffering_bytes, 200);
        assert_eq!(deltas.offload_submissions, 20);
        assert_eq!(state.total_resets, 1, "one boundary per worker observation");
        // Cumulative never decreases.
        assert_eq!(state.cumulative.body_buffering_bytes, 1700);
        assert_eq!(state.cumulative.offload_submissions, 120);
    }

    #[test]
    fn production_pruning_bounds_retained_bridge_state() {
        let mut state = BridgeState::default();
        let payload = empty_payload();
        let _ = state.apply_worker(WorkerId(1), 1, &payload);
        let _ = state.apply_worker(WorkerId(2), 1, &payload);
        assert_eq!(state.worker_counter_state.len(), 2);
        // Simulate a ProcessManager snapshot where worker 2 disappeared.
        let mut live = HashSet::new();
        live.insert(WorkerId(1));
        state.prune_to_live(&live);
        assert_eq!(state.worker_counter_state.len(), 1);
        assert!(state.worker_counter_state.contains_key(&WorkerId(1)));
    }

    #[test]
    fn repeated_remove_readd_remains_bounded_with_new_generation() {
        let mut state = BridgeState::default();
        let payload = empty_payload();
        for generation in 1..=10u64 {
            let _ = state.apply_worker(WorkerId(1), generation, &payload);
            // Each generation is pruned to the live set on refresh; state
            // holds at most the live worker regardless of history length.
            let mut live = HashSet::new();
            live.insert(WorkerId(1));
            state.prune_to_live(&live);
            assert_eq!(state.worker_counter_state.len(), 1);
        }
        // Ten generations produced nine boundaries (first is not a reset).
        assert_eq!(state.total_resets, 9);
    }

    #[test]
    fn retire_bounds_memory() {
        let mut state = BridgeState::default();
        let id = WorkerId(1);
        let payload = empty_payload();
        let _ = state.apply_worker(id, 1, &payload);
        state.retire(id);
        assert!(state.worker_counter_state.is_empty());
    }

    #[test]
    fn cpu_worker_aggregation_uses_latest_ready() {
        let mut snap = BridgeSnapshot::default();
        let mut cpu = CpuOffloadStats::default();
        cpu.worker_rss_bytes = 1024;
        snap.apply_cpu_worker(Some(&cpu));
        assert_eq!(snap.cpu_worker_rss_bytes, Some(1024));
        cpu.worker_rss_bytes = 2048;
        snap.apply_cpu_worker(Some(&cpu));
        assert_eq!(snap.cpu_worker_rss_bytes, Some(2048));
    }

    #[test]
    fn contract_id_is_stable_v2() {
        assert_eq!(CONTRACT_ID, "synvoid.eggbench-telemetry.v2");
        assert_eq!(
            CONTRACT_SCHEMA_VERSION,
            "synvoid.eggbench-telemetry.contract.v2"
        );
    }

    #[test]
    fn body_buffering_uses_bytes_and_offload_counters_use_count() {
        assert_eq!(OwnerMetric::BodyBufferingBytesTotal.unit(), "bytes");
        for m in [
            OwnerMetric::OffloadSubmissionsTotal,
            OwnerMetric::OffloadTimeoutsTotal,
            OwnerMetric::OffloadRejectionsTotal,
            OwnerMetric::OffloadFallbacksTotal,
            OwnerMetric::WorkerMetricResetsTotal,
        ] {
            assert_eq!(m.unit(), "count", "{:?} must use count", m);
        }
    }

    #[test]
    fn source_aggregation_is_distinct_from_trial_aggregation() {
        // Owner/source aggregation (supervisor across workers at one
        // instant) vs trial aggregation (Eggbench across scrapes).
        assert_eq!(OwnerMetric::ActiveConnections.source_aggregation(), "sum");
        assert_eq!(
            OwnerMetric::ActiveConnections.trial_aggregation(),
            Some("max")
        );
        assert_eq!(OwnerMetric::WorkerCpuPercent.source_aggregation(), "sum");
        assert_eq!(
            OwnerMetric::WorkerCpuPercent.trial_aggregation(),
            Some("mean")
        );
        // Counters carry no trial aggregation.
        for m in [
            OwnerMetric::BodyBufferingBytesTotal,
            OwnerMetric::OffloadSubmissionsTotal,
            OwnerMetric::OffloadTimeoutsTotal,
            OwnerMetric::OffloadRejectionsTotal,
            OwnerMetric::OffloadFallbacksTotal,
            OwnerMetric::WorkerMetricResetsTotal,
        ] {
            assert_eq!(
                m.trial_aggregation(),
                None,
                "{:?} must have no trial aggregation",
                m
            );
        }
        // Gauges carry only mean|max|min.
        for m in [
            OwnerMetric::EventLoopLagMs,
            OwnerMetric::RequestQueueP95Ms,
            OwnerMetric::ActiveConnections,
            OwnerMetric::WorkerMemoryBytes,
            OwnerMetric::WorkerCpuPercent,
            OwnerMetric::CpuWorkerRssBytes,
        ] {
            assert!(
                matches!(m.trial_aggregation(), Some("mean" | "max" | "min")),
                "{:?} trial aggregation must be mean|max|min",
                m
            );
        }
    }
    #[test]
    fn every_required_metric_has_a_distinct_prometheus_name() {
        let mut seen = std::collections::HashSet::new();
        for m in OWNER_INVENTORY.iter().filter(|m| m.required()) {
            assert!(seen.insert(m.prometheus_name()));
        }
    }

    #[test]
    fn gauges_and_counters_are_partitioned() {
        for m in OWNER_INVENTORY {
            match m.kind() {
                OwnerMetricKind::Gauge => {
                    assert!(
                        matches!(
                            m,
                            OwnerMetric::EventLoopLagMs
                                | OwnerMetric::RequestQueueP95Ms
                                | OwnerMetric::ActiveConnections
                                | OwnerMetric::WorkerMemoryBytes
                                | OwnerMetric::WorkerCpuPercent
                                | OwnerMetric::CpuWorkerRssBytes
                        ),
                        "{:?} is marked gauge but is not in gauge set",
                        m
                    );
                }
                OwnerMetricKind::Counter => {
                    assert!(
                        matches!(
                            m,
                            OwnerMetric::BodyBufferingBytesTotal
                                | OwnerMetric::OffloadSubmissionsTotal
                                | OwnerMetric::OffloadTimeoutsTotal
                                | OwnerMetric::OffloadRejectionsTotal
                                | OwnerMetric::OffloadFallbacksTotal
                                | OwnerMetric::WorkerMetricResetsTotal
                        ),
                        "{:?} is marked counter but is not in counter set",
                        m
                    );
                }
            }
        }
    }

    #[test]
    fn no_high_cardinality_labels_in_inventory() {
        // The contract is aggregate/no-label. Every metric name ends in
        // a stable suffix (no `{label}` placeholders) and the
        // `source_aggregation` does not reference per-worker IDs.
        for m in OWNER_INVENTORY {
            assert!(!m.prometheus_name().contains('{'));
            assert!(!m.source_aggregation().contains("worker_id"));
            assert!(!m.source_aggregation().contains("site_id"));
            assert!(!m.source_aggregation().contains("path"));
        }
    }
}
