use parking_lot::RwLock;
use rand::Rng;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::broadcast;
use tokio::time;

use crate::honeypot_port::config::PortHoneypotConfig;
use crate::honeypot_port::listener::PortHoneypotListener;
use crate::honeypot_port::storage::HoneypotStorage;
use crate::honeypot_port::threat_intel::HoneypotIntelExtractor;
use crate::mesh::protocol::ThreatType;
use crate::mesh::threat_intel::ThreatIntelligenceManager;

pub struct PortHoneypotRunner {
    config: Arc<PortHoneypotConfig>,
    storage: Arc<HoneypotStorage>,
    listener: Arc<PortHoneypotListener>,
    running: Arc<RwLock<bool>>,
    shutdown_tx: broadcast::Sender<()>,
}

impl PortHoneypotRunner {
    pub fn new(config: PortHoneypotConfig) -> Result<Arc<Self>, Box<dyn std::error::Error>> {
        let storage = Arc::new(HoneypotStorage::new(&config.storage)?);

        let config = Arc::new(config);
        let listener = PortHoneypotListener::new((*config).clone(), (*storage).clone());

        let (shutdown_tx, _) = broadcast::channel(1);

        Ok(Arc::new(Self {
            config,
            storage,
            listener,
            running: Arc::new(RwLock::new(false)),
            shutdown_tx,
        }))
    }

    pub fn storage(&self) -> &Arc<HoneypotStorage> {
        &self.storage
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

    pub async fn run(self: &Arc<Self>) {
        {
            let mut running = self.running.write();
            if *running {
                tracing::warn!("Port honeypot runner already running");
                return;
            }
            *running = true;
        }

        let _shutdown_rx = self.shutdown_tx.subscribe();

        let storage = self.storage.clone();
        tokio::spawn(async move {
            storage.prune_old_records().ok();
            storage.enforce_max_records().ok();
        });

        let prune_storage = self.storage.clone();
        tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(3600));
            loop {
                interval.tick().await;
                if let Err(e) = prune_storage.prune_old_records() {
                    tracing::error!("Failed to prune honeypot records: {}", e);
                }
                if let Err(e) = prune_storage.enforce_max_records() {
                    tracing::error!("Failed to enforce max records: {}", e);
                }
            }
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

        {
            let mut running = self.running.write();
            *running = false;
        }
    }

    pub fn stop(&self) {
        let _ = self.shutdown_tx.send(());
        let mut running = self.running.write();
        *running = false;
    }

    pub fn start_mesh_threat_publishing(
        self: &Arc<Self>,
        threat_intel: Arc<ThreatIntelligenceManager>,
        publish_interval_secs: u64,
    ) {
        let storage = self.storage.clone();
        let threat_intel = threat_intel.clone();
        let site_scope = self.config.site_scope.clone();

        tokio::spawn(async move {
            let mut interval = time::interval(Duration::from_secs(publish_interval_secs));
            let mut last_timestamp: i64 = storage
                .get_metadata("mesh_publish_cursor")
                .ok()
                .flatten()
                .and_then(|s| s.parse::<i64>().ok())
                .unwrap_or(0);

            loop {
                interval.tick().await;

                if let Ok(records) = storage.get_records_since(last_timestamp, 100) {
                    if records.is_empty() {
                        continue;
                    }

                    let mut announced_ips: std::collections::HashSet<String> =
                        storage.get_announced_indicator_keys().unwrap_or_default();
                    let mut records_processed = 0i64;

                    for record in &records {
                        records_processed += 1;
                        let indicators = HoneypotIntelExtractor::extract_indicators(record);

                        for indicator in indicators {
                            let threat_type = match indicator.indicator_type {
                                crate::honeypot_port::threat_intel::IndicatorType::SourceIp => ThreatType::IpBlock,
                                crate::honeypot_port::threat_intel::IndicatorType::AttackPattern => ThreatType::SuspiciousActivity,
                                crate::honeypot_port::threat_intel::IndicatorType::AttackVector => ThreatType::SuspiciousActivity,
                                crate::honeypot_port::threat_intel::IndicatorType::Payload => ThreatType::SuspiciousActivity,
                            };

                            let severity = match indicator.severity {
                                crate::honeypot_port::threat_intel::SeverityLevel::Critical => {
                                    crate::mesh::protocol::ThreatSeverity::Critical
                                }
                                crate::honeypot_port::threat_intel::SeverityLevel::High => {
                                    crate::mesh::protocol::ThreatSeverity::High
                                }
                                crate::honeypot_port::threat_intel::SeverityLevel::Medium => {
                                    crate::mesh::protocol::ThreatSeverity::Medium
                                }
                                crate::honeypot_port::threat_intel::SeverityLevel::Low => {
                                    crate::mesh::protocol::ThreatSeverity::Low
                                }
                            };

                            let publish_ip = match indicator.indicator_type {
                                crate::honeypot_port::threat_intel::IndicatorType::SourceIp => {
                                    indicator.value.parse::<std::net::IpAddr>().ok()
                                }
                                _ => record.remote_ip.parse::<std::net::IpAddr>().ok(),
                            };

                            if let Some(ip) = publish_ip {
                                let ip_str = ip.to_string();
                                if announced_ips.contains(&ip_str) {
                                    continue;
                                }
                                announced_ips.insert(ip_str.clone());

                                if let Err(e) = storage.mark_indicator_announced(&ip_str) {
                                    tracing::warn!("Failed to persist announced indicator: {}", e);
                                }

                                threat_intel.announce_honeypot_indicator(
                                    ip,
                                    threat_type,
                                    severity,
                                    indicator.description,
                                    Some(3600 * 24),
                                    &site_scope,
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
                        "Published honeypot indicators: {} unique IPs, {} records processed",
                        announced_ips.len(),
                        records_processed
                    );

                    crate::metrics::record_honeypot_indicators_published(announced_ips.len() as u64);
                    crate::metrics::record_honeypot_records_processed(records_processed as u64);
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
