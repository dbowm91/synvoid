use parking_lot::RwLock;
use rand::Rng;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;
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

pub struct PortHoneypotRunner {
    config: Arc<PortHoneypotConfig>,
    storage: Arc<HoneypotStorage>,
    writer: Arc<HoneypotWriter>,
    listener: Arc<PortHoneypotListener>,
    running: Arc<RwLock<bool>>,
    shutdown_tx: broadcast::Sender<()>,
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

        let (shutdown_tx, _) = broadcast::channel(1);

        Ok(Arc::new(Self {
            config,
            storage: Arc::new(storage),
            writer: Arc::new(writer),
            listener,
            running: Arc::new(RwLock::new(false)),
            shutdown_tx,
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
        *self.running.read()
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
    async fn maintenance_loop<F, Fut>(
        mut shutdown_rx: broadcast::Receiver<()>,
        interval: Duration,
        mut operation: F,
    ) where
        F: FnMut() -> Fut,
        Fut: std::future::Future<Output = ()>,
    {
        operation().await;
        loop {
            tokio::select! {
                _ = time::sleep(interval) => {
                    operation().await;
                }
                _ = shutdown_rx.recv() => {
                    break;
                }
            }
        }
    }

    /// Production maintenance task: initial prune/max-record pass once, then
    /// one hourly cycle. The `sleep`-based wait avoids the immediate second
    /// tick of `interval()`.
    async fn maintenance_task(
        storage: Arc<HoneypotStorage>,
        shutdown_rx: broadcast::Receiver<()>,
        interval: Duration,
    ) {
        Self::maintenance_loop(shutdown_rx, interval, || async {
            Self::run_storage_maintenance(storage.clone()).await;
        })
        .await;
    }

    pub async fn run(self: &Arc<Self>) {
        {
            let mut running = self.running.write();
            if *running {
                tracing::warn!("Port honeypot runner already running");
                return;
            }
            *running = true;
        }

        // Phase 56: subscribe before spawning so the stop signal cannot be
        // missed, then own exactly one maintenance lifecycle for this run.
        let maintenance_shutdown_rx = self.shutdown_tx.subscribe();
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
            let port = self.select_random_port();

            tracing::info!("Starting port honeypot on port {}", port);

            let listener = self.listener.clone();

            let rotation_interval = self.rotation_interval();
            tracing::debug!("Next rotation in {} seconds", rotation_interval.as_secs());

            let mut shutdown_rx2 = self.shutdown_tx.subscribe();
            let listener_for_shutdown = self.listener.clone();

            let shutdown_received = tokio::select! {
                _ = async {
                    listener.start_on_port(port).await
                } => {
                    tracing::debug!("Listener finished, switching ports");
                    false
                }
                _ = time::sleep(rotation_interval) => {
                    listener_for_shutdown.shutdown();
                    tracing::debug!("Rotation interval reached, switching ports");
                    false
                }
                _ = shutdown_rx2.recv() => {
                    listener_for_shutdown.shutdown();
                    tracing::info!("Port honeypot shutting down");
                    true
                }
            };

            if shutdown_received {
                break;
            }

            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        // Phase 56: the periodic maintenance task is owned by this run. The
        // shutdown broadcast is already sent by `stop()`; awaiting here
        // guarantees no maintenance task survives successful return from
        // `run()` and no new cycle starts after shutdown. An in-progress
        // blocking SQLite operation may finish during this await.
        if let Err(join_err) = maintenance_handle.await {
            tracing::error!("Honeypot maintenance task failed: {}", join_err);
        }
        // Converge on the same idempotent writer completion as `stop()` so a
        // runner shutdown always drains queued records before returning.
        self.writer.shutdown().await;

        {
            let mut running = self.running.write();
            *running = false;
        }
    }

    pub fn stop(&self) {
        let _ = self.shutdown_tx.send(());
        let mut running = self.running.write();
        *running = false;
        let writer = self.writer.clone();
        tokio::spawn(async move {
            writer.shutdown().await;
        });
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
    #[tokio::test]
    async fn test_maintenance_initial_runs_once_not_twice() {
        let (tx, rx) = broadcast::channel(1);
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
        let _ = tx.send(());
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
        let (tx, rx) = broadcast::channel(1);
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
        let _ = tx.send(());
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
        let (tx, rx) = broadcast::channel(1);
        let handle = tokio::spawn(async move {
            PortHoneypotRunner::maintenance_loop(rx, Duration::from_secs(3600), || async {
                tokio::task::yield_now().await;
            })
            .await;
        });
        let _ = tx.send(());
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
            let (tx, rx) = broadcast::channel(1);
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
            let _ = tx.send(());
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
        let (tx, rx) = broadcast::channel(1);
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
        let _ = tx.send(());
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
