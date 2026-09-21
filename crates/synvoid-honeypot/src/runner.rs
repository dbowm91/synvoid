use parking_lot::{Mutex, RwLock};
use rand::Rng;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::watch;
use tokio::time;

use crate::config::PortHoneypotConfig;
use crate::listener::PortHoneypotListener;
use crate::responders::AiResponderBudget;
use crate::storage::HoneypotStorage;
use crate::storage_writer::HoneypotWriter;
#[cfg(feature = "mesh")]
use crate::threat_intel::HoneypotIntelExtractor;
#[cfg(feature = "mesh")]
use synvoid_mesh::protocol::ThreatType;
#[cfg(feature = "mesh")]
use synvoid_mesh::threat_intel::ThreatIntelligenceManager;

/// Phase 57: private runner lifecycle ownership, separate from the
/// user-visible `is_running()` status.
///
/// - `Idle`: never started; the only state from which `run()` may acquire
///   ownership.
/// - `Running`: one active `run()` lifecycle owns listener selection,
///   maintenance, and writer drain. `is_running()` reports true only here.
/// - `Stopping`: `stop()` has requested durable shutdown. `is_running()`
///   already reports false, but lifecycle ownership is still held until
///   teardown completes, so a second `run()` must be rejected.
/// - `Stopped`: terminal. Teardown (listener exit, maintenance join, writer
///   drain) has completed. Because `HoneypotWriter::shutdown()` is terminal,
///   one runner instance is one lifecycle; a second `run()` after `Stopped`
///   must not start a partial lifecycle.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RunnerLifecycle {
    Idle,
    Running,
    Stopping,
    Stopped,
}

pub struct PortHoneypotRunner {
    config: Arc<PortHoneypotConfig>,
    storage: Arc<HoneypotStorage>,
    writer: Arc<HoneypotWriter>,
    listener: Arc<PortHoneypotListener>,
    lifecycle: Arc<Mutex<RunnerLifecycle>>,
    shutdown_tx: watch::Sender<bool>,
    /// Phase 57 test-only teardown barrier. Production code never sets this;
    /// lifecycle tests install a `Notify` gate to hold teardown in `Stopping`
    /// deterministically while a second `run()` is attempted. Not an
    /// operator-facing knob.
    #[cfg(test)]
    teardown_gate: Arc<Mutex<Option<Arc<tokio::sync::Notify>>>>,
}

impl PortHoneypotRunner {
    pub fn new(config: PortHoneypotConfig) -> Result<Arc<Self>, Box<dyn std::error::Error>> {
        let storage = HoneypotStorage::new(&config.storage)?;
        let writer = HoneypotWriter::new(storage.clone(), config.storage.writer.clone());

        // Build AI responder budget when mode is not Disabled
        let ai_budget = config
            .ai_config
            .as_ref()
            .filter(|c| c.mode != crate::config::AiResponderMode::Disabled)
            .map(|c| Arc::new(AiResponderBudget::new(c.budget.clone())));

        let config = Arc::new(config);
        let listener = PortHoneypotListener::new((*config).clone(), writer.clone(), ai_budget);

        // Phase 57: stateful cancellation. `watch` retains `true` once `stop()`
        // requests shutdown, so a receiver subscribing after the request still
        // observes it. No edge-triggered loss window.
        let (shutdown_tx, _) = watch::channel(false);

        Ok(Arc::new(Self {
            config,
            storage: Arc::new(storage),
            writer: Arc::new(writer),
            listener,
            lifecycle: Arc::new(Mutex::new(RunnerLifecycle::Idle)),
            shutdown_tx,
            #[cfg(test)]
            teardown_gate: Arc::new(Mutex::new(None)),
        }))
    }

    pub fn storage(&self) -> &Arc<HoneypotStorage> {
        &self.storage
    }

    pub fn writer(&self) -> &Arc<HoneypotWriter> {
        &self.writer
    }

    pub fn listener(&self) -> &Arc<PortHoneypotListener> {
        &self.listener
    }

    pub fn current_port(&self) -> u16 {
        self.listener.current_port()
    }

    pub fn is_running(&self) -> bool {
        *self.lifecycle.lock() == RunnerLifecycle::Running
    }

    /// Phase 57 terminal contract: one runner instance is one lifecycle.
    ///
    /// `run()` may transition the instance from idle to active once. After
    /// terminal shutdown begins/completes, the same instance must not start a
    /// second overlapping or partially-functional lifecycle, because
    /// `HoneypotWriter::shutdown()` is terminal (intake closes, queued
    /// records drain, later writes fail). A future operational
    /// "enable after disable" feature must construct a new runner/writer
    /// instance unless a separate plan makes the writer restartable.
    ///
    /// `is_running()` retains its user-facing meaning: true only while
    /// actively serving (`Running`). It reports false once `Stopping` begins,
    /// but that visible status is no longer the guard permitting a second
    /// lifecycle; the private `RunnerLifecycle` ownership guard blocks overlap
    /// through `Stopping` until terminal `Stopped`.
    #[cfg(test)]
    pub(crate) fn test_lifecycle(&self) -> RunnerLifecycle {
        *self.lifecycle.lock()
    }

    #[cfg(test)]
    pub(crate) fn test_lifecycle_name(&self) -> &'static str {
        match self.test_lifecycle() {
            RunnerLifecycle::Idle => "Idle",
            RunnerLifecycle::Running => "Running",
            RunnerLifecycle::Stopping => "Stopping",
            RunnerLifecycle::Stopped => "Stopped",
        }
    }

    /// Install a deterministic teardown hold for lifecycle tests. The active
    /// `run()` awaits the returned gate after maintenance join and writer
    /// drain, before marking terminal `Stopped`. Tests release with
    /// `gate.notify_one()`. Production never installs a gate.
    #[cfg(test)]
    pub(crate) fn install_teardown_gate(&self) -> Arc<tokio::sync::Notify> {
        let gate = Arc::new(tokio::sync::Notify::new());
        *self.teardown_gate.lock() = Some(gate.clone());
        gate
    }

    #[cfg(test)]
    pub(crate) fn clear_teardown_gate(&self) {
        *self.teardown_gate.lock() = None;
    }

    /// Hourly SQLite maintenance interval for the runner-owned task.
    pub const MAINTENANCE_INTERVAL: Duration = Duration::from_secs(3600);

    /// Single bounded blocking maintenance operation. Synchronous SQLite
    /// work runs on `spawn_blocking`, never on a Tokio core worker.
    async fn run_storage_maintenance(storage: Arc<HoneypotStorage>) {
        let result = tokio::task::spawn_blocking(move || {
            if let Err(e) = storage.prune_old_records() {
                tracing::error!("Failed to prune honeypot records: {}", e);
            }
            if let Err(e) = storage.enforce_max_records() {
                tracing::error!("Failed to enforce max records: {}", e);
            }
        })
        .await;
        if let Err(join_err) = result {
            tracing::error!("Honeypot maintenance task failed: {}", join_err);
        }
    }

    /// Lifecycle-owned maintenance loop shared by production and tests.
    ///
    /// Phase 56: exactly one initial maintenance pass runs, then each cycle
    /// awaits one bounded blocking operation before the next wait, so at most
    /// one SQLite maintenance operation is ever in flight and cycles can
    /// never overlap. The loop exits on the shutdown receiver without
    /// starting a new cycle.
    ///
    /// Phase 57: the shutdown signal is a stateful `watch<bool>`. A receiver
    /// subscribing after `stop()` already observes `true`, so an early stop
    /// cannot be lost to a late subscription. No sleeps, repeated sends, or
    /// polling.
    /// Durable shutdown wait on a stateful `watch<bool>`: returns once the
    /// value is `true` or the sender is gone. `borrow()` pre-checks make a
    /// stop requested before the wait observable; `changed()` wakes on a
    /// later request. The returned `()` is `Send`, unlike `wait_for`'s
    /// lock-guarded `Ref`, so this can run inside spawned (`Send`) futures.
    async fn shutdown_requested(rx: &mut watch::Receiver<bool>) {
        loop {
            if *rx.borrow() {
                return;
            }
            if rx.changed().await.is_err() {
                return;
            }
        }
    }

    async fn maintenance_loop<F, Fut>(
        shutdown_rx: watch::Receiver<bool>,
        interval: Duration,
        mut operation: F,
    ) where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        operation().await;
        if *shutdown_rx.borrow() {
            return;
        }
        loop {
            // Clone for the wait branch so `borrow()` on the canonical
            // receiver does not conflict with the mutable wait borrow inside
            // the same `select!`.
            let mut shutdown_wait = shutdown_rx.clone();
            tokio::select! {
                biased;
                _ = Self::shutdown_requested(&mut shutdown_wait) => {
                    break;
                }
                _ = time::sleep(interval) => {
                    if *shutdown_rx.borrow() {
                        break;
                    }
                    operation().await;
                    if *shutdown_rx.borrow() {
                        break;
                    }
                }
            }
        }
    }

    /// Production maintenance task: initial prune/max-record pass once, then
    /// one hourly cycle. The `sleep`-based wait avoids the immediate second
    /// tick of `interval()`.
    async fn maintenance_task(
        storage: Arc<HoneypotStorage>,
        shutdown_rx: watch::Receiver<bool>,
        interval: Duration,
    ) {
        Self::maintenance_loop(shutdown_rx, interval, || async {
            Self::run_storage_maintenance(storage.clone()).await;
        })
        .await;
    }

    pub async fn run(self: &Arc<Self>) {
        // Phase 57: durable shutdown. Subscribe before acquiring lifecycle
        // ownership so the receivers exist before the instance is externally
        // visible as active. `watch` retains a requested stop, so even a
        // `stop()` racing acquisition is observed via `borrow()`/`wait_for`.
        let maintenance_shutdown_rx = self.shutdown_tx.subscribe();
        let main_shutdown_rx = self.shutdown_tx.subscribe();

        {
            let mut guard = self.lifecycle.lock();
            if *guard != RunnerLifecycle::Idle {
                tracing::warn!("Port honeypot runner already running or terminal");
                return;
            }
            *guard = RunnerLifecycle::Running;
        }

        // Phase 56 (retained): own exactly one maintenance lifecycle for this
        // run. Phase 57 carries the same watch cancellation into it.
        let maintenance_storage = self.storage.clone();
        let maintenance_handle = tokio::spawn(async move {
            Self::maintenance_task(
                maintenance_storage,
                maintenance_shutdown_rx,
                Self::MAINTENANCE_INTERVAL,
            )
            .await;
        });

        loop {
            // Durable pre-check: a stop requested before this iteration must
            // not start new listener work. `biased` selection below additionally
            // prioritizes shutdown when it races listener completion.
            if *main_shutdown_rx.borrow() {
                break;
            }
            let port = self.select_random_port();

            tracing::info!("Starting port honeypot on port {}", port);

            let listener = self.listener.clone();

            let rotation_interval = self.rotation_interval();
            tracing::debug!("Next rotation in {} seconds", rotation_interval.as_secs());

            let listener_for_shutdown = self.listener.clone();
            let listener_for_rotation = self.listener.clone();
            // Clone for the wait branch; `borrow()` on `main_shutdown_rx`
            // must not overlap a mutable wait borrow in one `select!`.
            let mut shutdown_wait = main_shutdown_rx.clone();

            let shutdown_received = tokio::select! {
                biased;
                _ = Self::shutdown_requested(&mut shutdown_wait) => {
                    listener_for_shutdown.shutdown();
                    tracing::info!("Port honeypot shutting down");
                    true
                }
                _ = async {
                    listener.start_on_port(port).await
                } => {
                    if *main_shutdown_rx.borrow() {
                        listener_for_shutdown.shutdown();
                        tracing::info!("Port honeypot shutting down");
                        true
                    } else {
                        tracing::debug!("Listener finished, switching ports");
                        false
                    }
                }
                _ = time::sleep(rotation_interval) => {
                    if *main_shutdown_rx.borrow() {
                        listener_for_shutdown.shutdown();
                        tracing::info!("Port honeypot shutting down");
                        true
                    } else {
                        listener_for_rotation.shutdown();
                        tracing::debug!("Rotation interval reached, switching ports");
                        false
                    }
                }
            };

            if shutdown_received {
                break;
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        // Phase 56 (retained): the periodic maintenance task is owned by this
        // run. Awaiting here guarantees no maintenance task survives
        // successful return from `run()` and no new cycle starts after
        // shutdown. An in-progress blocking SQLite operation may finish during
        // this await. Phase 57: `stop()` no longer spawns a concurrent writer
        // shutdown for the active lifecycle; this path is the single owner of
        // listener shutdown, maintenance join, and writer drain.
        if let Err(join_err) = maintenance_handle.await {
            tracing::error!("Honeypot maintenance task failed: {}", join_err);
        }
        // `HoneypotWriter::shutdown()` is idempotent and stateful (Phase 56);
        // `run()` does not return before queued records have drained.
        self.writer.shutdown().await;

        // Phase 57 test-only deterministic barrier: hold terminal transition
        // in `Stopping` while a test attempts a second `run()`. Production
        // never installs a gate. The lock guard is dropped before the await
        // so the future stays `Send` (`parking_lot` guards are `!Send`).
        #[cfg(test)]
        {
            let gate_opt = { self.teardown_gate.lock().clone() };
            if let Some(gate) = gate_opt {
                gate.notified().await;
            }
        }

        {
            let mut guard = self.lifecycle.lock();
            *guard = RunnerLifecycle::Stopped;
        }
    }

    pub fn stop(&self) {
        // Phase 57: durable synchronous cancellation request. `watch` retains
        // `true` so a stop racing `run()` acquisition cannot be lost to a late
        // subscription. Repeated calls are idempotent.
        let _ = self.shutdown_tx.send(true);
        let previous = {
            let mut guard = self.lifecycle.lock();
            let previous = *guard;
            if previous == RunnerLifecycle::Running {
                *guard = RunnerLifecycle::Stopping;
            }
            previous
        };
        // Phase 57 Workstream D single ownership: the active `run()` path owns
        // listener shutdown, maintenance join, and writer drain, so `stop()`
        // must not spawn a concurrent writer shutdown for the active
        // lifecycle and must not release ownership early (`Stopping` still
        // blocks a second `run()`; only the terminal transition after drain
        // marks `Stopped`).
        //
        // If no run lifecycle was ever active (`Idle`), arrange writer closure
        // separately so an never-started instance does not leak its writer
        // task. A pending `run()` that later acquires `Idle` still observes
        // the durable watch shutdown, skips listener work, drains (idempotent
        // with this spawn), and marks terminal. Requires a Tokio runtime, as
        // did the Phase 56 `stop()` spawn; outside a runtime the pending
        // `run()` remains responsible for the drain.
        if previous == RunnerLifecycle::Idle && tokio::runtime::Handle::try_current().is_ok() {
            let writer = self.writer.clone();
            tokio::spawn(async move {
                writer.shutdown().await;
            });
        }
    }

    #[cfg(feature = "mesh")]
    pub fn start_mesh_threat_publishing(
        self: &Arc<Self>,
        threat_intel: Arc<ThreatIntelligenceManager>,
        publish_interval_secs: u64,
    ) {
        let storage = self.storage.clone();
        let threat_intel = threat_intel.clone();
        let site_scope = self.config.site_scope.clone();
        let scoring_config = self.config.threat_intel.scoring.clone();

        tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(publish_interval_secs));
            let mut last_timestamp: i64 = storage
                .get_metadata("mesh_publish_cursor")
                .ok()
                .flatten()
                .and_then(|s| s.parse::<i64>().ok())
                .unwrap_or(0);

            let mut announced_keys: std::collections::HashSet<String> =
                storage.get_announced_indicator_keys().unwrap_or_default();

            loop {
                interval.tick().await;

                if let Ok(records) = storage.get_records_since(last_timestamp, 100) {
                    if records.is_empty() {
                        continue;
                    }

                    let mut records_processed = 0i64;
                    let mut indicators_published = 0u64;
                    let mut indicators_skipped = 0u64;

                    for record in &records {
                        records_processed += 1;
                        let indicators = HoneypotIntelExtractor::extract_indicators(record);

                        for indicator in indicators {
                            let signal_class = match indicator.indicator_type {
                                crate::threat_intel::IndicatorType::SourceIp => {
                                    crate::threat_intel::SignalClass::ProtocolProbe
                                }
                                crate::threat_intel::IndicatorType::AttackPattern => {
                                    crate::threat_intel::SignalClass::KnownAttackPattern
                                }
                                crate::threat_intel::IndicatorType::AttackVector => {
                                    crate::threat_intel::SignalClass::ExploitPayload
                                }
                                crate::threat_intel::IndicatorType::Payload => {
                                    crate::threat_intel::SignalClass::ExploitPayload
                                }
                            };

                            let dedupe_key =
                                crate::threat_intel::HoneypotIntelExtractor::compute_dedupe_key(
                                    &indicator.indicator_type,
                                    &indicator.value,
                                );

                            if announced_keys.contains(&dedupe_key) {
                                indicators_skipped += 1;
                                continue;
                            }

                            let score =
                                crate::threat_intel::HoneypotIntelExtractor::score_indicator(
                                    &scoring_config,
                                    record,
                                    &signal_class,
                                    1,
                                    1,
                                    0,
                                );

                            if !score.action_class.allows_mesh_propagation() {
                                indicators_skipped += 1;
                                tracing::debug!(
                                    "Honeypot indicator {} scored {:.2} action={:?}, skipping mesh publish",
                                    dedupe_key,
                                    score.score,
                                    score.action_class
                                );
                                continue;
                            }

                            let threat_type = match indicator.indicator_type {
                                crate::threat_intel::IndicatorType::SourceIp => ThreatType::IpBlock,
                                _ => ThreatType::SuspiciousActivity,
                            };

                            let severity = match indicator.severity {
                                crate::threat_intel::SeverityLevel::Critical => {
                                    synvoid_mesh::protocol::ThreatSeverity::Critical
                                }
                                crate::threat_intel::SeverityLevel::High => {
                                    synvoid_mesh::protocol::ThreatSeverity::High
                                }
                                crate::threat_intel::SeverityLevel::Medium => {
                                    synvoid_mesh::protocol::ThreatSeverity::Medium
                                }
                                crate::threat_intel::SeverityLevel::Low => {
                                    synvoid_mesh::protocol::ThreatSeverity::Low
                                }
                            };

                            let publish_ip = match indicator.indicator_type {
                                crate::threat_intel::IndicatorType::SourceIp => {
                                    indicator.value.parse::<std::net::IpAddr>().ok()
                                }
                                _ => record.remote_ip.parse::<std::net::IpAddr>().ok(),
                            };

                            if let Some(ip) = publish_ip {
                                announced_keys.insert(dedupe_key.clone());

                                if let Err(e) = storage.mark_indicator_announced(&dedupe_key) {
                                    tracing::warn!("Failed to persist announced indicator: {}", e);
                                }

                                threat_intel.announce_honeypot_indicator(
                                    ip,
                                    threat_type,
                                    severity,
                                    indicator.description,
                                    Some(scoring_config.mesh_ttl_secs),
                                    &site_scope,
                                );

                                indicators_published += 1;
                                tracing::debug!(
                                    "Published honeypot indicator: key={} score={:.2} action={:?}",
                                    dedupe_key,
                                    score.score,
                                    score.action_class
                                );
                            }
                        }

                        last_timestamp = record.timestamp.max(last_timestamp);
                    }

                    if let Err(e) =
                        storage.set_metadata("mesh_publish_cursor", &last_timestamp.to_string())
                    {
                        tracing::warn!("Failed to persist mesh publish cursor: {}", e);
                    }

                    tracing::debug!(
                        "Honeypot mesh publishing: {} records, {} published, {} skipped",
                        records_processed,
                        indicators_published,
                        indicators_skipped
                    );
                }
            }
        });
    }

    fn select_random_port(&self) -> u16 {
        let mut rng = rand::rng();
        let range = self.config.max_port - self.config.min_port;
        self.config.min_port + rng.random_range(0..=range)
    }

    fn rotation_interval(&self) -> Duration {
        let mut rng = rand::rng();
        let range = self.config.max_rotation_interval_secs - self.config.min_rotation_interval_secs;
        let secs = self.config.min_rotation_interval_secs + rng.random_range(0..=range);
        Duration::from_secs(secs)
    }
}

pub struct RateLimitedPortHoneypot {
    runner: Arc<PortHoneypotRunner>,
    rate_limiter: Option<Arc<dyn HoneypotRateLimiter + Send + Sync>>,
    enabled: Arc<RwLock<bool>>,
}

#[async_trait::async_trait]
pub trait HoneypotRateLimiter: Send + Sync {
    async fn check_rate_limit(&self, ip: &str) -> RateLimitResult;
}

#[derive(Debug, Clone)]
pub struct RateLimitResult {
    pub allowed: bool,
    pub remaining: i64,
    pub reset_secs: i64,
}

impl RateLimitedPortHoneypot {
    pub fn new(
        runner: Arc<PortHoneypotRunner>,
        rate_limiter: Option<Arc<dyn HoneypotRateLimiter + Send + Sync>>,
    ) -> Self {
        Self {
            runner,
            rate_limiter,
            enabled: Arc::new(RwLock::new(true)),
        }
    }

    pub fn is_enabled(&self) -> bool {
        *self.enabled.read()
    }

    pub fn set_enabled(&self, enabled: bool) {
        *self.enabled.write() = enabled;
    }

    pub fn disable(&self) {
        self.set_enabled(false);
    }

    pub fn enable(&self) {
        self.set_enabled(true);
    }

    pub fn storage(&self) -> &Arc<HoneypotStorage> {
        self.runner.storage()
    }

    pub fn listener(&self) -> &Arc<PortHoneypotListener> {
        self.runner.listener()
    }

    pub async fn should_accept_connection(&self, ip: &str) -> bool {
        if !self.is_enabled() {
            return false;
        }

        if let Some(ref limiter) = self.rate_limiter {
            let result = limiter.check_rate_limit(ip).await;
            if !result.allowed {
                tracing::debug!("Connection from {} blocked by rate limiter", ip);
                return false;
            }
        }

        true
    }

    pub fn current_port(&self) -> u16 {
        self.runner.current_port()
    }
}

#[cfg(test)]
mod runner_maintenance_tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    /// Phase 56: initial maintenance executes exactly once when shutdown
    /// arrives before the first periodic interval elapses.
    /// Phase 57: shutdown is stateful `watch<bool>`; retained here.
    #[tokio::test]
    async fn test_maintenance_initial_runs_once_not_twice() {
        let (tx, rx) = watch::channel(false);
        let count = Arc::new(AtomicUsize::new(0));
        let count_clone = count.clone();
        let handle = tokio::spawn(async move {
            PortHoneypotRunner::maintenance_loop(rx, Duration::from_secs(3600), || async {
                count_clone.fetch_add(1, Ordering::SeqCst);
            })
            .await;
        });
        // Let the initial pass run, then stop well before the hourly tick.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let _ = tx.send(true);
        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("maintenance task must exit on shutdown")
            .expect("maintenance task must not panic");
        assert_eq!(
            count.load(Ordering::SeqCst),
            1,
            "initial maintenance must execute exactly once, not twice"
        );
    }

    /// Phase 56: periodic maintenance never overlaps itself. The operation
    /// asserts single-flight with an in-flight flag across several short
    /// cycles.
    #[tokio::test]
    async fn test_maintenance_periodic_does_not_overlap() {
        let (tx, rx) = watch::channel(false);
        let count = Arc::new(AtomicUsize::new(0));
        let in_flight = Arc::new(AtomicBool::new(false));
        let overlapped = Arc::new(AtomicBool::new(false));
        let count_clone = count.clone();
        let in_flight_clone = in_flight.clone();
        let overlapped_clone = overlapped.clone();
        let handle = tokio::spawn(async move {
            PortHoneypotRunner::maintenance_loop(rx, Duration::from_millis(20), || async {
                if in_flight_clone.swap(true, Ordering::SeqCst) {
                    overlapped_clone.store(true, Ordering::SeqCst);
                }
                count_clone.fetch_add(1, Ordering::SeqCst);
                tokio::time::sleep(Duration::from_millis(35)).await;
                in_flight_clone.store(false, Ordering::SeqCst);
            })
            .await;
        });
        tokio::time::sleep(Duration::from_millis(200)).await;
        let _ = tx.send(true);
        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("maintenance task must exit")
            .expect("no panic");
        assert!(
            !overlapped.load(Ordering::SeqCst),
            "maintenance cycles must never overlap"
        );
        assert!(
            count.load(Ordering::SeqCst) >= 2,
            "periodic cycles should have run"
        );
    }

    /// Phase 56: stop causes the maintenance task to exit promptly, and the
    /// owning `run()` await pattern (join on the handle) completes.
    #[tokio::test]
    async fn test_maintenance_stop_exits_task() {
        let (tx, rx) = watch::channel(false);
        let handle = tokio::spawn(async move {
            PortHoneypotRunner::maintenance_loop(rx, Duration::from_secs(3600), || async {
                tokio::task::yield_now().await;
            })
            .await;
        });
        let _ = tx.send(true);
        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("maintenance task must exit after stop")
            .expect("no panic");
    }

    /// Phase 56: `run()`-style ownership awaits the maintenance handle, so
    /// return implies no live periodic task. A restart creates one new
    /// lifecycle rather than accumulating tasks.
    #[tokio::test]
    async fn test_maintenance_restart_creates_single_lifecycle() {
        for _ in 0..2 {
            let (tx, rx) = watch::channel(false);
            let count = Arc::new(AtomicUsize::new(0));
            let count_clone = count.clone();
            // Mimic one `run()` ownership: spawn, stop, await join.
            let handle = tokio::spawn(async move {
                PortHoneypotRunner::maintenance_loop(rx, Duration::from_millis(15), || async {
                    count_clone.fetch_add(1, Ordering::SeqCst);
                })
                .await;
            });
            tokio::time::sleep(Duration::from_millis(60)).await;
            let _ = tx.send(true);
            tokio::time::timeout(Duration::from_secs(5), handle)
                .await
                .expect("each lifecycle must be joinable on stop")
                .expect("no panic");
            assert!(
                count.load(Ordering::SeqCst) >= 1,
                "each restart must create one new maintenance lifecycle"
            );
        }
    }

    /// Phase 56: no new cycle starts after shutdown, even if the interval
    /// elapses while an in-progress operation finishes.
    #[tokio::test]
    async fn test_maintenance_no_new_cycle_after_shutdown() {
        let (tx, rx) = watch::channel(false);
        let count = Arc::new(AtomicUsize::new(0));
        let count_clone = count.clone();
        let handle = tokio::spawn(async move {
            PortHoneypotRunner::maintenance_loop(rx, Duration::from_millis(30), || async {
                count_clone.fetch_add(1, Ordering::SeqCst);
                // In-progress blocking work finishing during shutdown.
                tokio::time::sleep(Duration::from_millis(60)).await;
            })
            .await;
        });
        // Initial pass starts immediately; stop while it is in flight.
        tokio::time::sleep(Duration::from_millis(10)).await;
        let _ = tx.send(true);
        tokio::time::timeout(Duration::from_secs(5), handle)
            .await
            .expect("must exit")
            .expect("no panic");
        let after_stop = count.load(Ordering::SeqCst);
        tokio::time::sleep(Duration::from_millis(80)).await;
        assert_eq!(
            count.load(Ordering::SeqCst),
            after_stop,
            "no new maintenance cycle may start after shutdown"
        );
    }
}

#[cfg(test)]
mod runner_lifecycle_tests {
    use super::*;
    use crate::config::{PortHoneypotConfig, StorageConfig};

    /// Isolated loopback-safe runner: ephemeral port (0), 127.0.0.1 bind,
    /// long rotation so tests exit via `stop()`, in-memory SQLite so no
    /// filesystem state leaks between tests.
    fn test_runner() -> Arc<PortHoneypotRunner> {
        let mut config = PortHoneypotConfig::default();
        config.enabled = true;
        config.bind_address = std::net::IpAddr::from([127, 0, 0, 1]);
        config.min_port = 0;
        config.max_port = 0;
        config.min_rotation_interval_secs = 3600;
        config.max_rotation_interval_secs = 3600;
        config.storage = StorageConfig {
            database_path: ":memory:".to_string(),
            ..Default::default()
        };
        PortHoneypotRunner::new(config).expect("test runner builds")
    }

    async fn wait_until_running(runner: &Arc<PortHoneypotRunner>) {
        tokio::time::timeout(Duration::from_secs(5), async {
            while !runner.is_running() {
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("runner must become Running");
    }

    async fn wait_until_state(runner: &Arc<PortHoneypotRunner>, want: RunnerLifecycle) {
        let want_name = match want {
            RunnerLifecycle::Idle => "Idle",
            RunnerLifecycle::Running => "Running",
            RunnerLifecycle::Stopping => "Stopping",
            RunnerLifecycle::Stopped => "Stopped",
        };
        tokio::time::timeout(Duration::from_secs(5), async {
            loop {
                if runner.test_lifecycle() == want {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .unwrap_or_else(|_| {
            panic!(
                "runner must reach {want_name}, currently {}",
                runner.test_lifecycle_name()
            )
        });
    }

    /// Phase 57.1: an early `stop()` cannot be lost. The real `run()` task
    /// must exit within a bounded timeout even when `stop()` races lifecycle
    /// acquisition. `watch` retains the request; there is no late-subscriber
    /// window.
    #[tokio::test]
    async fn test_runner_early_stop_cannot_be_lost() {
        let runner = test_runner();
        assert!(!runner.is_running());
        assert_eq!(runner.test_lifecycle(), RunnerLifecycle::Idle);

        let handle = tokio::spawn({
            let runner = runner.clone();
            async move { runner.run().await }
        });
        wait_until_running(&runner).await;
        // Issue stop as early as deterministically possible: synchronously
        // after observing active state, without yielding to teardown first.
        runner.stop();

        tokio::time::timeout(Duration::from_secs(10), handle)
            .await
            .expect("real run() must return after early stop, not hang")
            .expect("run() must not panic");
        assert_eq!(runner.test_lifecycle(), RunnerLifecycle::Stopped);
        assert!(!runner.is_running());
    }

    /// Phase 57.2: `stop()` does not release lifecycle ownership early. While
    /// teardown is held at a deterministic test barrier (`Stopping`), a
    /// second `run()` must return without starting listener/maintenance work.
    #[tokio::test]
    async fn test_runner_stop_does_not_release_ownership_early() {
        let runner = test_runner();
        let gate = runner.install_teardown_gate();

        let mut first = tokio::spawn({
            let runner = runner.clone();
            async move { runner.run().await }
        });
        wait_until_running(&runner).await;
        runner.stop();
        // Visible status flips immediately, but ownership stays held.
        assert!(
            !runner.is_running(),
            "is_running() must report false once Stopping begins"
        );
        wait_until_state(&runner, RunnerLifecycle::Stopping).await;

        // Second lifecycle attempted while first teardown is gated: must be
        // rejected promptly. The early return performs no await before the
        // lifecycle check, so this is deterministic without yielding to the
        // first task.
        tokio::time::timeout(Duration::from_secs(2), runner.run())
            .await
            .expect("second run() while Stopping must return promptly, not hang");
        assert_eq!(
            runner.test_lifecycle(),
            RunnerLifecycle::Stopping,
            "second run() must not advance lifecycle out of Stopping"
        );
        assert!(
            !runner.is_running(),
            "no second serving lifecycle may become visible"
        );
        assert!(
            !first.is_finished(),
            "first run() must still own teardown while gated"
        );

        gate.notify_one();
        tokio::time::timeout(Duration::from_secs(10), &mut first)
            .await
            .expect("first run() must complete after gate release")
            .expect("no panic");
        assert_eq!(runner.test_lifecycle(), RunnerLifecycle::Stopped);
        runner.clear_teardown_gate();
    }

    /// Phase 57.3: real `run()` return owns maintenance. `run()` awaits the
    /// maintenance handle, so return implies the periodic task observed
    /// shutdown and exited. If maintenance ignored shutdown, this `run()`
    /// would hang on the hourly sleep past the timeout.
    #[tokio::test]
    async fn test_runner_teardown_owns_maintenance() {
        let runner = test_runner();
        let handle = tokio::spawn({
            let runner = runner.clone();
            async move { runner.run().await }
        });
        wait_until_running(&runner).await;
        runner.stop();
        tokio::time::timeout(Duration::from_secs(10), handle)
            .await
            .expect("run() must return, implying maintenance joined after stop")
            .expect("no panic");
        assert_eq!(runner.test_lifecycle(), RunnerLifecycle::Stopped);
        assert!(!runner.is_running());
    }

    /// Phase 57.4: repeated `stop()` is idempotent. Several sync callers
    /// converge on one `run()` exit and one writer drain without hang/panic.
    #[tokio::test]
    async fn test_runner_repeated_stop_idempotent() {
        let runner = test_runner();
        let handle = tokio::spawn({
            let runner = runner.clone();
            async move { runner.run().await }
        });
        wait_until_running(&runner).await;

        // Synchronous burst plus concurrent callers.
        runner.stop();
        runner.stop();
        let r2 = runner.clone();
        let r3 = runner.clone();
        tokio::join!(
            async move {
                r2.stop();
                r2.stop();
            },
            async move {
                r3.stop();
            }
        );
        runner.stop();

        tokio::time::timeout(Duration::from_secs(10), handle)
            .await
            .expect("one real run() must exit after repeated stop()")
            .expect("no panic");

        // Writer drain completed exactly once; late shutdown returns promptly
        // and intake stays closed.
        tokio::time::timeout(Duration::from_secs(2), runner.writer().shutdown())
            .await
            .expect("late writer shutdown must return promptly");
        assert!(
            runner
                .writer()
                .try_write_record(crate::storage::HoneypotRecord {
                    id: 0,
                    timestamp: 1700000000,
                    remote_ip: "127.0.0.1".to_string(),
                    remote_port: 12345,
                    local_port: 0,
                    protocol: "http".to_string(),
                    service: "http".to_string(),
                    confidence: crate::protocol::Confidence::Low,
                    payload: b"GET / HTTP/1.0\r\n\r\n".to_vec(),
                    payload_hex: String::new(),
                    detected_pattern: None,
                    bytes_received: 0,
                    bytes_sent: 0,
                    duration_ms: 0,
                    connection_info: "test".to_string(),
                    payload_truncated: false,
                    payload_hash: None,
                    payload_length: None,
                })
                .is_err(),
            "writes after terminal drain must fail closed"
        );
    }

    /// Phase 57.5: terminal same-instance behavior. After the first real
    /// `run()` fully returns, a second `run()` on the terminal instance must
    /// not create a partial second lifecycle (writer intake is already
    /// closed). Operational re-enable must construct a new runner/writer.
    #[tokio::test]
    async fn test_runner_terminal_same_instance_no_second_lifecycle() {
        let runner = test_runner();
        let handle = tokio::spawn({
            let runner = runner.clone();
            async move { runner.run().await }
        });
        wait_until_running(&runner).await;
        runner.stop();
        tokio::time::timeout(Duration::from_secs(10), handle)
            .await
            .expect("first run() must complete")
            .expect("no panic");
        assert_eq!(runner.test_lifecycle(), RunnerLifecycle::Stopped);

        tokio::time::timeout(Duration::from_secs(2), runner.run())
            .await
            .expect("second run() on terminal instance must return promptly");
        assert_eq!(
            runner.test_lifecycle(),
            RunnerLifecycle::Stopped,
            "terminal instance must not leave Stopped"
        );
        assert!(
            !runner.is_running(),
            "terminal instance must never report serving again"
        );
    }

    /// Phase 57.6: status truth. `is_running()` is true only in `Running`;
    /// the internal guard still blocks overlap while `Stopping`, even though
    /// the visible status is already false.
    #[tokio::test]
    async fn test_runner_status_truth_vs_ownership() {
        let runner = test_runner();
        assert!(!runner.is_running());
        assert_eq!(runner.test_lifecycle(), RunnerLifecycle::Idle);

        let gate = runner.install_teardown_gate();
        let mut first = tokio::spawn({
            let runner = runner.clone();
            async move { runner.run().await }
        });
        wait_until_running(&runner).await;
        assert_eq!(runner.test_lifecycle(), RunnerLifecycle::Running);
        assert!(runner.is_running());

        runner.stop();
        assert!(
            !runner.is_running(),
            "visible status must flip at Stopping, before teardown completes"
        );
        wait_until_state(&runner, RunnerLifecycle::Stopping).await;
        assert!(
            !runner.is_running(),
            "Stopping must stay visibly stopped while ownership is held"
        );

        tokio::time::timeout(Duration::from_secs(2), runner.run())
            .await
            .expect("overlapping run() during Stopping must be rejected promptly");
        assert_eq!(runner.test_lifecycle(), RunnerLifecycle::Stopping);

        gate.notify_one();
        tokio::time::timeout(Duration::from_secs(10), &mut first)
            .await
            .expect("first run() must reach terminal")
            .expect("no panic");
        assert_eq!(runner.test_lifecycle(), RunnerLifecycle::Stopped);
        assert!(!runner.is_running());
        runner.clear_teardown_gate();
    }
}
