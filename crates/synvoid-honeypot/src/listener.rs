use parking_lot::RwLock;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, OwnedSemaphorePermit, Semaphore};
use tokio::time;

use crate::config::PortHoneypotConfig;
use crate::protocol::ProtocolDetector;
use crate::storage::{HoneypotRecord, HoneypotStorage};
use synvoid_utils::current_timestamp;

/// RAII guard that decrements per-IP connection count on drop.
/// When the count reaches zero, the entry is removed from the map.
pub(crate) struct IpConnGuard {
    ip_counts: Arc<RwLock<HashMap<String, usize>>>,
    ip_key: String,
}

impl IpConnGuard {
    pub(crate) fn new(ip_counts: Arc<RwLock<HashMap<String, usize>>>, ip_key: String) -> Self {
        Self { ip_counts, ip_key }
    }
}

impl Drop for IpConnGuard {
    fn drop(&mut self) {
        let mut counts = self.ip_counts.write();
        if let Some(c) = counts.get_mut(&self.ip_key) {
            *c = c.saturating_sub(1);
            if *c == 0 {
                counts.remove(&self.ip_key);
            }
        }
    }
}

pub struct PortHoneypotListener {
    config: Arc<PortHoneypotConfig>,
    storage: Arc<HoneypotStorage>,
    detector: Arc<ProtocolDetector>,
    current_port: Arc<RwLock<u16>>,
    active_connections: Arc<AtomicUsize>,
    shutdown_tx: broadcast::Sender<()>,
    ip_connection_counts: Arc<RwLock<HashMap<String, usize>>>,
    global_semaphore: Arc<Semaphore>,
}

#[derive(Debug, Clone)]
pub struct ConnectionEvent {
    pub remote_ip: String,
    pub remote_port: u16,
    pub local_port: u16,
    pub service: String,
    pub protocol: String,
    pub detected_pattern: Option<String>,
    pub payload_hex: String,
}

impl PortHoneypotListener {
    pub fn new(config: PortHoneypotConfig, storage: HoneypotStorage) -> Arc<Self> {
        let (shutdown_tx, _) = broadcast::channel(1);
        let max_concurrent = config.max_concurrent_connections;

        Arc::new(Self {
            config: Arc::new(config),
            storage: Arc::new(storage),
            detector: Arc::new(ProtocolDetector::new()),
            current_port: Arc::new(RwLock::new(0)),
            active_connections: Arc::new(AtomicUsize::new(0)),
            shutdown_tx,
            ip_connection_counts: Arc::new(RwLock::new(HashMap::new())),
            global_semaphore: Arc::new(Semaphore::new(max_concurrent)),
        })
    }

    pub fn current_port(&self) -> u16 {
        *self.current_port.read()
    }

    pub fn active_connections(&self) -> usize {
        self.active_connections.load(Ordering::Relaxed)
    }

    pub async fn is_port_available(&self, port: u16) -> bool {
        let addr = SocketAddr::new(self.config.bind_address, port);
        TcpListener::bind(addr).await.is_ok()
    }

    pub async fn find_available_port(
        &self,
        min_port: u16,
        max_port: u16,
        max_attempts: usize,
    ) -> Option<u16> {
        use rand::Rng;

        let mut rng = rand::rng();
        let ports: Vec<u16> = (min_port..=max_port).collect();

        for _ in 0..max_attempts {
            let idx = rng.random_range(0..ports.len());
            let port = ports[idx];

            if self.is_port_available(port).await {
                return Some(port);
            }
        }

        None
    }

    pub async fn start_on_port(&self, port: u16) -> Result<(), std::io::Error> {
        let addr = SocketAddr::new(self.config.bind_address, port);

        let listener = match TcpListener::bind(addr).await {
            Ok(l) => l,
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::AddrInUse,
                    format!("Port {} is already in use", port),
                ));
            }
            Err(e) => return Err(e),
        };

        *self.current_port.write() = port;

        tracing::info!("Port honeypot listening on {}", addr);

        let mut shutdown_rx = self.shutdown_tx.subscribe();

        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, remote_addr)) => {
                            let ip_key = remote_addr.ip().to_string();

                            // Try to acquire a global semaphore permit
                            let global_permit = match Arc::clone(&self.global_semaphore).try_acquire_owned() {
                                Ok(p) => p,
                                Err(_) => {
                                    metrics::counter!("honeypot_connections_rejected_global_limit").increment(1);
                                    tracing::debug!(
                                        remote_ip = %remote_addr.ip(),
                                        "Honeypot connection rejected: global limit reached"
                                    );
                                    drop(stream);
                                    continue;
                                }
                            };

                            // Check per-IP connection limit
                            {
                                let counts = self.ip_connection_counts.read();
                                if let Some(&count) = counts.get(&ip_key) {
                                    if count >= self.config.max_connections_per_ip {
                                        metrics::counter!("honeypot_connections_rejected_per_ip_limit").increment(1);
                                        tracing::debug!(
                                            remote_ip = %remote_addr.ip(),
                                            current_count = count,
                                            max = self.config.max_connections_per_ip,
                                            "Honeypot connection rejected: per-IP limit reached"
                                        );
                                        drop(global_permit);
                                        drop(stream);
                                        continue;
                                    }
                                }
                            }

                            // Increment per-IP count and create RAII guard
                            {
                                let mut counts = self.ip_connection_counts.write();
                                let count = counts.entry(ip_key.clone()).or_insert(0);
                                *count += 1;
                            }
                            let ip_guard = IpConnGuard::new(
                                Arc::clone(&self.ip_connection_counts),
                                ip_key,
                            );

                            let config = self.config.clone();
                            let storage = self.storage.clone();
                            let detector = self.detector.clone();
                            let active = self.active_connections.clone();

                            metrics::counter!("honeypot_connections_accepted").increment(1);

                            tokio::spawn(async move {
                                active.fetch_add(1, Ordering::Relaxed);
                                handle_connection(
                                    stream,
                                    remote_addr,
                                    port,
                                    &config,
                                    &storage,
                                    &detector,
                                    global_permit,
                                    ip_guard,
                                )
                                .await;
                                active.fetch_sub(1, Ordering::Relaxed);
                            });
                        }
                        Err(e) => {
                            tracing::error!("Accept error: {}", e);
                        }
                    }
                }
                _ = shutdown_rx.recv() => {
                    break;
                }
            }
        }

        Ok(())
    }

    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(());
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) async fn handle_connection(
    mut stream: TcpStream,
    remote_addr: SocketAddr,
    local_port: u16,
    config: &PortHoneypotConfig,
    storage: &HoneypotStorage,
    detector: &ProtocolDetector,
    _global_permit: OwnedSemaphorePermit,
    _ip_guard: IpConnGuard,
) {
    let start = Instant::now();
    let max_payload = config.max_payload_size;
    let mut payload = Vec::with_capacity(max_payload.min(4096));
    let mut payload_truncated = false;
    let mut total_bytes_received: usize = 0;
    let mut total_bytes_sent: usize = 0;

    // Phase 1: Initial read with connection timeout
    let mut buf = [0u8; 4096];
    let initial_timeout = Duration::from_millis(config.connection_timeout_ms);

    let initial_read = match time::timeout(initial_timeout, stream.read(&mut buf)).await {
        Ok(Ok(0)) => {
            // EOF immediately — no data
            drop(_global_permit);
            drop(_ip_guard);
            return;
        }
        Ok(Ok(n)) => n,
        Ok(Err(e)) => {
            tracing::debug!(remote_ip = %remote_addr.ip(), error = %e, "Honeypot initial read error");
            metrics::counter!("honeypot_handler_errors").increment(1);
            drop(_global_permit);
            drop(_ip_guard);
            return;
        }
        Err(_) => {
            metrics::counter!("honeypot_connections_timed_out_initial").increment(1);
            tracing::debug!(remote_ip = %remote_addr.ip(), "Honeypot connection timed out (initial)");
            drop(_global_permit);
            drop(_ip_guard);
            return;
        }
    };

    total_bytes_received += initial_read;
    let remaining = max_payload.saturating_sub(payload.len());
    let take = initial_read.min(remaining);
    payload.extend_from_slice(&buf[..take]);
    if initial_read > remaining {
        payload_truncated = true;
    }

    // Protocol detection
    let detection = detector.detect(&payload);
    let (protocol, service) = detection
        .as_ref()
        .map(|d| (d.protocol.clone(), d.service.clone()))
        .unwrap_or_else(|| ("unknown".to_string(), "unknown".to_string()));

    // Banner lookup uses normalized protocol (lowercase)
    let banner = detector.get_banner_for_service(&protocol, local_port);

    // Send banner + response_for_payload
    if let Some(ref banner_data) = banner {
        let mut write_buf = banner_data.banner.clone();

        if !payload.is_empty() {
            if let Some(response) = &banner_data.response_for_payload {
                write_buf.extend_from_slice(response);
            }
        }

        let write_timeout = Duration::from_millis(config.connection_timeout_ms);
        total_bytes_sent += write_buf.len();

        if let Err(e) = time::timeout(write_timeout, stream.write_all(&write_buf)).await {
            tracing::debug!(remote_ip = %remote_addr.ip(), error = %e, "Honeypot write error");
        }
    }

    // Phase 2: Subsequent reads with read timeout
    let read_timeout = Duration::from_millis(config.read_timeout_ms);
    loop {
        if payload.len() >= max_payload {
            payload_truncated = true;
            break;
        }

        match time::timeout(read_timeout, stream.read(&mut buf)).await {
            Ok(Ok(0)) => break, // EOF
            Ok(Ok(n)) => {
                total_bytes_received += n;
                let remaining = max_payload.saturating_sub(payload.len());
                let take = n.min(remaining);
                if take > 0 {
                    payload.extend_from_slice(&buf[..take]);
                }
                if n > remaining {
                    payload_truncated = true;
                }
            }
            Ok(Err(e)) => {
                tracing::debug!(remote_ip = %remote_addr.ip(), error = %e, "Honeypot read error");
                metrics::counter!("honeypot_handler_errors").increment(1);
                break;
            }
            Err(_) => {
                metrics::counter!("honeypot_connections_timed_out_read").increment(1);
                tracing::debug!(remote_ip = %remote_addr.ip(), "Honeypot connection timed out (read)");
                break;
            }
        }
    }

    if payload_truncated {
        metrics::counter!("honeypot_payload_truncated").increment(1);
    }

    let duration = start.elapsed();

    let record = HoneypotRecord {
        id: 0,
        timestamp: current_timestamp() as i64,
        remote_ip: remote_addr.ip().to_string(),
        remote_port: remote_addr.port(),
        local_port,
        protocol: protocol.clone(),
        service: service.clone(),
        payload: payload.clone(),
        payload_hex: hex::encode(&payload),
        detected_pattern: detection.as_ref().and_then(|d| d.matched_pattern.clone()),
        bytes_received: total_bytes_received as u32,
        bytes_sent: total_bytes_sent as u32,
        duration_ms: duration.as_millis() as u32,
        connection_info: format!("{}:{}", remote_addr.ip(), remote_addr.port()),
        payload_truncated,
    };

    if let Err(e) = storage.record_connection(record) {
        tracing::error!("Failed to record honeypot connection: {}", e);
        metrics::counter!("honeypot_storage_insert_failures").increment(1);
    }

    tracing::debug!(
        remote_ip = %remote_addr.ip(),
        remote_port = remote_addr.port(),
        local_port,
        protocol = %protocol,
        service = %service,
        bytes_received = total_bytes_received,
        bytes_sent = total_bytes_sent,
        duration_ms = duration.as_millis(),
        payload_truncated,
        "Honeypot connection recorded"
    );
}
