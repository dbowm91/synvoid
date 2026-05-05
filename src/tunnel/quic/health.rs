use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use metrics::{counter, gauge, histogram};
use quinn::Connection;
use serde::{Deserialize, Serialize};
use tokio::sync::{broadcast, mpsc};

use crate::tunnel::quic::messages::DatagramCapabilities;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HealthCheckConfig {
    pub interval_secs: u64,
    pub timeout_secs: u64,
    pub failure_threshold: u32,
    pub recovery_threshold: u32,
    pub rtt_warning_threshold_ms: u64,
    pub rtt_critical_threshold_ms: u64,
    pub loss_rate_warning_threshold: f64,
    pub loss_rate_critical_threshold: f64,
    #[serde(default = "default_check_timeout_ms")]
    pub check_timeout_ms: u64,
}

fn default_check_timeout_ms() -> u64 {
    500
}

impl Default for HealthCheckConfig {
    fn default() -> Self {
        Self {
            interval_secs: 10,
            timeout_secs: 5,
            failure_threshold: 3,
            recovery_threshold: 2,
            rtt_warning_threshold_ms: 100,
            rtt_critical_threshold_ms: 500,
            loss_rate_warning_threshold: 0.05,
            loss_rate_critical_threshold: 0.15,
            check_timeout_ms: 500,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnectionQuality {
    Excellent,
    Good,
    Degraded,
    Poor,
    Failed,
}

impl ConnectionQuality {
    pub fn is_usable(&self) -> bool {
        matches!(self, Self::Excellent | Self::Good | Self::Degraded)
    }

    pub fn should_reconnect(&self) -> bool {
        matches!(self, Self::Poor | Self::Failed)
    }
}

#[derive(Debug, Clone)]
pub struct ConnectionHealth {
    pub session_id: String,
    pub peer_id: Option<String>,
    pub quality: ConnectionQuality,
    pub consecutive_failures: u32,
    pub consecutive_successes: u32,
    pub last_check: Instant,
    pub last_success: Option<Instant>,
    pub last_failure: Option<Instant>,
    pub avg_rtt_ms: f64,
    pub recent_rtts: Vec<Duration>,
    pub packets_sent: u64,
    pub packets_lost: u64,
    pub loss_rate: f64,
    pub datagram_capabilities: DatagramCapabilities,
}

impl ConnectionHealth {
    pub fn new(session_id: String, peer_id: Option<String>) -> Self {
        Self {
            session_id,
            peer_id,
            quality: ConnectionQuality::Good,
            consecutive_failures: 0,
            consecutive_successes: 0,
            last_check: Instant::now(),
            last_success: None,
            last_failure: None,
            avg_rtt_ms: 0.0,
            recent_rtts: Vec::with_capacity(10),
            packets_sent: 0,
            packets_lost: 0,
            loss_rate: 0.0,
            datagram_capabilities: DatagramCapabilities::default(),
        }
    }

    pub fn record_rtt(&mut self, rtt: Duration) {
        self.recent_rtts.push(rtt);
        if self.recent_rtts.len() > 10 {
            self.recent_rtts.remove(0);
        }

        let total: Duration = self.recent_rtts.iter().sum();
        self.avg_rtt_ms = total.as_secs_f64() * 1000.0 / self.recent_rtts.len() as f64;
    }

    pub fn record_packet_sent(&mut self) {
        self.packets_sent += 1;
        self.update_loss_rate();
    }

    pub fn record_packet_loss(&mut self) {
        self.packets_lost += 1;
        self.update_loss_rate();
    }

    fn update_loss_rate(&mut self) {
        if self.packets_sent > 0 {
            self.loss_rate = self.packets_lost as f64 / self.packets_sent as f64;
        }
    }

    pub fn update_quality(&mut self, config: &HealthCheckConfig) {
        let rtt_quality = if self.avg_rtt_ms == 0.0 {
            ConnectionQuality::Good
        } else if self.avg_rtt_ms < config.rtt_warning_threshold_ms as f64 {
            ConnectionQuality::Excellent
        } else if self.avg_rtt_ms < config.rtt_critical_threshold_ms as f64 {
            ConnectionQuality::Good
        } else {
            ConnectionQuality::Degraded
        };

        let loss_quality = if self.loss_rate < config.loss_rate_warning_threshold {
            ConnectionQuality::Excellent
        } else if self.loss_rate < config.loss_rate_critical_threshold {
            ConnectionQuality::Degraded
        } else {
            ConnectionQuality::Poor
        };

        let failure_quality = match self.consecutive_failures {
            0 => ConnectionQuality::Excellent,
            1 => ConnectionQuality::Good,
            2 => ConnectionQuality::Degraded,
            _ if self.consecutive_failures >= config.failure_threshold => ConnectionQuality::Failed,
            _ => ConnectionQuality::Poor,
        };

        self.quality = std::cmp::max(std::cmp::max(rtt_quality, loss_quality), failure_quality);
    }
}

impl std::cmp::PartialOrd for ConnectionQuality {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl std::cmp::Ord for ConnectionQuality {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        let order = |q: &ConnectionQuality| match q {
            ConnectionQuality::Excellent => 0,
            ConnectionQuality::Good => 1,
            ConnectionQuality::Degraded => 2,
            ConnectionQuality::Poor => 3,
            ConnectionQuality::Failed => 4,
        };
        order(self).cmp(&order(other))
    }
}

pub struct QuicHealthMonitor {
    config: HealthCheckConfig,
    connections: Arc<DashMap<String, ConnectionHealth>>,
    shutdown_tx: broadcast::Sender<()>,
    health_event_tx: mpsc::Sender<HealthEvent>,
}

#[derive(Debug, Clone)]
pub enum HealthEvent {
    QualityChanged {
        session_id: String,
        peer_id: Option<String>,
        old_quality: ConnectionQuality,
        new_quality: ConnectionQuality,
    },
    ConnectionFailed {
        session_id: String,
        peer_id: Option<String>,
        reason: String,
    },
    ConnectionRecovered {
        session_id: String,
        peer_id: Option<String>,
    },
    RttWarning {
        session_id: String,
        rtt_ms: f64,
    },
    PacketLossWarning {
        session_id: String,
        loss_rate: f64,
    },
}

impl QuicHealthMonitor {
    pub fn new(config: HealthCheckConfig) -> (Self, mpsc::Receiver<HealthEvent>) {
        let (shutdown_tx, _) = broadcast::channel(1);
        let (health_event_tx, health_event_rx) = mpsc::channel(100);

        (
            Self {
                config,
                connections: Arc::new(DashMap::new()),
                shutdown_tx,
                health_event_tx,
            },
            health_event_rx,
        )
    }

    pub fn register_connection(&self, session_id: String, peer_id: Option<String>) {
        let health = ConnectionHealth::new(session_id.clone(), peer_id.clone());
        self.connections.insert(session_id, health);
        gauge!("synvoid.tunnel.quic.health.monitored_connections")
            .set(self.connections.len() as f64);
    }

    pub fn unregister_connection(&self, session_id: &str) {
        self.connections.remove(session_id);
        gauge!("synvoid.tunnel.quic.health.monitored_connections")
            .set(self.connections.len() as f64);
    }

    pub fn set_datagram_capabilities(&self, session_id: &str, caps: DatagramCapabilities) {
        if let Some(mut health) = self.connections.get_mut(session_id) {
            health.datagram_capabilities = caps;
        }
    }

    pub fn record_health_check_success(&self, session_id: &str, rtt: Duration) {
        if let Some(mut health) = self.connections.get_mut(session_id) {
            let old_quality = health.quality;

            health.consecutive_failures = 0;
            health.consecutive_successes += 1;
            health.last_check = Instant::now();
            health.last_success = Some(Instant::now());
            health.record_rtt(rtt);
            health.update_quality(&self.config);

            histogram!("synvoid.tunnel.quic.health.rtt").record(rtt.as_secs_f64() * 1000.0);

            if health.consecutive_successes == self.config.recovery_threshold
                && (old_quality == ConnectionQuality::Failed
                    || old_quality == ConnectionQuality::Poor)
            {
                let _ = self
                    .health_event_tx
                    .try_send(HealthEvent::ConnectionRecovered {
                        session_id: session_id.to_string(),
                        peer_id: health.peer_id.clone(),
                    });
                counter!("synvoid.tunnel.quic.health.recovered").increment(1);
            }

            if old_quality != health.quality {
                let _ = self.health_event_tx.try_send(HealthEvent::QualityChanged {
                    session_id: session_id.to_string(),
                    peer_id: health.peer_id.clone(),
                    old_quality,
                    new_quality: health.quality,
                });
            }
        }
    }

    pub fn record_health_check_failure(&self, session_id: &str, reason: &str) {
        if let Some(mut health) = self.connections.get_mut(session_id) {
            let old_quality = health.quality;

            health.consecutive_successes = 0;
            health.consecutive_failures += 1;
            health.last_check = Instant::now();
            health.last_failure = Some(Instant::now());
            health.update_quality(&self.config);

            counter!("synvoid.tunnel.quic.health.failures").increment(1);

            if health.consecutive_failures >= self.config.failure_threshold {
                let _ = self
                    .health_event_tx
                    .try_send(HealthEvent::ConnectionFailed {
                        session_id: session_id.to_string(),
                        peer_id: health.peer_id.clone(),
                        reason: reason.to_string(),
                    });
            }

            if old_quality != health.quality {
                let _ = self.health_event_tx.try_send(HealthEvent::QualityChanged {
                    session_id: session_id.to_string(),
                    peer_id: health.peer_id.clone(),
                    old_quality,
                    new_quality: health.quality,
                });
            }
        }
    }

    pub fn record_packet_stats(&self, session_id: &str, sent: u64, lost: u64) {
        if let Some(mut health) = self.connections.get_mut(session_id) {
            let was_loss_rate = health.loss_rate;

            health.packets_sent += sent;
            health.packets_lost += lost;
            health.update_loss_rate();
            health.update_quality(&self.config);

            if health.loss_rate > self.config.loss_rate_warning_threshold
                && was_loss_rate <= self.config.loss_rate_warning_threshold
            {
                let _ = self
                    .health_event_tx
                    .try_send(HealthEvent::PacketLossWarning {
                        session_id: session_id.to_string(),
                        loss_rate: health.loss_rate,
                    });
            }

            if health.avg_rtt_ms > self.config.rtt_warning_threshold_ms as f64 {
                let _ = self.health_event_tx.try_send(HealthEvent::RttWarning {
                    session_id: session_id.to_string(),
                    rtt_ms: health.avg_rtt_ms,
                });
            }
        }
    }

    pub fn get_connection_quality(&self, session_id: &str) -> Option<ConnectionQuality> {
        self.connections.get(session_id).map(|h| h.quality)
    }

    pub fn get_connection_health(&self, session_id: &str) -> Option<ConnectionHealth> {
        self.connections.get(session_id).map(|h| h.clone())
    }

    pub fn get_all_health(&self) -> Vec<ConnectionHealth> {
        self.connections.iter().map(|e| e.value().clone()).collect()
    }

    pub async fn start_monitoring(&self, connections: Arc<DashMap<String, Connection>>) {
        let config = self.config.clone();
        let health_connections = self.connections.clone();
        let shutdown_rx = self.shutdown_tx.subscribe();
        let event_tx = self.health_event_tx.clone();
        let max_concurrent_checks = 50usize;
        let semaphore = Arc::new(tokio::sync::Semaphore::new(max_concurrent_checks));

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(config.interval_secs));
            let mut shutdown = shutdown_rx;

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        let connections_snapshot: Vec<(String, Connection)> = connections
                            .iter()
                            .filter_map(|entry| {
                                let session_id = entry.key().clone();
                                let connection = entry.value().clone();

                                if let Some(health) = health_connections.get(&session_id) {
                                    if health.quality.is_usable() {
                                        return Some((session_id, connection));
                                    }
                                }
                                None
                            })
                            .collect();

                        for (session_id, connection) in connections_snapshot {
                            let health_connections_clone = health_connections.clone();
                            let event_tx_clone = event_tx.clone();
                            let config_clone = config.clone();
                            let semaphore_clone = semaphore.clone();

                            let permit = match semaphore_clone.clone().acquire_owned().await {
                                Ok(p) => p,
                                Err(_) => continue,
                            };

                            tokio::spawn(async move {
                                let start = Instant::now();

                                tokio::select! {
                                    _ = connection.closed() => {
                                        if let Some(mut health) = health_connections_clone.get_mut(&session_id) {
                                            health.consecutive_successes = 0;
                                            health.consecutive_failures += 1;
                                            health.last_failure = Some(Instant::now());
                                            health.update_quality(&config_clone);

                                            if health.consecutive_failures >= config_clone.failure_threshold {
                                                let _ = event_tx_clone.try_send(HealthEvent::ConnectionFailed {
                                                    session_id: session_id.clone(),
                                                    peer_id: health.peer_id.clone(),
                                                    reason: "Connection closed".to_string(),
                                                });
                                            }
                                        }
                                    }
                                    _ = tokio::time::sleep(Duration::from_millis(config_clone.check_timeout_ms)) => {
                                        let rtt = start.elapsed();
                                        if let Some(mut health) = health_connections_clone.get_mut(&session_id) {
                                            health.consecutive_failures = 0;
                                            health.consecutive_successes += 1;
                                            health.last_check = Instant::now();
                                            health.last_success = Some(Instant::now());
                                            health.record_rtt(rtt);
                                            health.update_quality(&config_clone);
                                        }
                                    }
                                }
                                drop(permit);
                            });
                        }
                    }
                    _ = shutdown.recv() => {
                        tracing::info!("Health monitor shutting down");
                        break;
                    }
                }
            }
        });

        tracing::info!(
            "QUIC health monitor started with interval {}s, max concurrent checks: {}",
            self.config.interval_secs,
            max_concurrent_checks
        );
    }

    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(());
    }
}
