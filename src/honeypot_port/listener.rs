use parking_lot::RwLock;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::broadcast;
use tokio::time;

use crate::honeypot_port::config::PortHoneypotConfig;
use crate::honeypot_port::protocol::ProtocolDetector;
use crate::honeypot_port::storage::{HoneypotRecord, HoneypotStorage};
use crate::utils::current_timestamp;

pub struct PortHoneypotListener {
    config: Arc<PortHoneypotConfig>,
    storage: Arc<HoneypotStorage>,
    detector: Arc<ProtocolDetector>,
    current_port: Arc<RwLock<u16>>,
    active_connections: Arc<AtomicUsize>,
    shutdown_tx: broadcast::Sender<()>,
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

        Arc::new(Self {
            config: Arc::new(config),
            storage: Arc::new(storage),
            detector: Arc::new(ProtocolDetector::new()),
            current_port: Arc::new(RwLock::new(0)),
            active_connections: Arc::new(AtomicUsize::new(0)),
            shutdown_tx,
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

        if !self.is_port_available(port).await {
            return Err(std::io::Error::new(
                std::io::ErrorKind::AddrInUse,
                format!("Port {} is already in use", port),
            ));
        }

        let listener = TcpListener::bind(addr).await?;

        *self.current_port.write() = port;

        tracing::info!("Port honeypot listening on {}", addr);

        let mut shutdown_rx = self.shutdown_tx.subscribe();

        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, remote_addr)) => {
                            if self.active_connections.load(Ordering::Relaxed) >= self.config.max_concurrent_connections {
                                tracing::warn!("Max concurrent connections reached, dropping connection from {}", remote_addr);
                                continue;
                            }

                            let config = self.config.clone();
                            let storage = self.storage.clone();
                            let detector = self.detector.clone();
                            let active = self.active_connections.clone();

                            tokio::spawn(async move {
                                active.fetch_add(1, Ordering::Relaxed);
                                handle_connection(stream, remote_addr, port, &config, &storage, &detector).await;
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

async fn handle_connection(
    mut stream: TcpStream,
    remote_addr: SocketAddr,
    local_port: u16,
    config: &PortHoneypotConfig,
    storage: &HoneypotStorage,
    detector: &ProtocolDetector,
) {
    let start = Instant::now();
    let mut payload = Vec::with_capacity(config.max_payload_size);
    let mut buf = [0u8; 2048];

    let read_timeout = Duration::from_millis(config.connection_timeout_ms);

    let bytes_read = match time::timeout(read_timeout, stream.read(&mut buf)).await {
        Ok(Ok(0)) => {
            return;
        }
        Ok(Ok(n)) => n,
        Ok(Err(e)) => {
            tracing::debug!("Read error from {}: {}", remote_addr, e);
            return;
        }
        Err(_) => {
            tracing::debug!("Read timeout from {}", remote_addr);
            return;
        }
    };

    payload.extend_from_slice(&buf[..bytes_read]);

    let detection = detector.detect(&payload);
    let (service, protocol) = detection
        .as_ref()
        .map(|d| (d.service.clone(), d.protocol.clone()))
        .unwrap_or_else(|| ("unknown".to_string(), "unknown".to_string()));

    let banner = detector.get_banner_for_service(&service, local_port);

    let banner_len = banner.as_ref().map(|b| b.banner.len()).unwrap_or(0);

    if let Some(ref banner_data) = banner {
        let mut write_buf = banner_data.banner.clone();

        if !payload.is_empty() {
            if let Some(response) = &banner_data.response_for_payload {
                write_buf.extend_from_slice(response);
            }
        }

        let write_timeout = Duration::from_millis(config.connection_timeout_ms);

        if let Err(e) = time::timeout(write_timeout, stream.write_all(&write_buf)).await {
            tracing::debug!("Write error to {}: {}", remote_addr, e);
        }

        let extra_read = time::timeout(
            Duration::from_millis(config.read_timeout_ms),
            stream.read(&mut buf),
        )
        .await
        .unwrap_or(Ok(0))
        .unwrap_or(0);

        if extra_read > 0 {
            payload.extend_from_slice(&buf[..extra_read]);
        }
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
        bytes_received: bytes_read as u32,
        bytes_sent: banner_len as u32,
        duration_ms: duration.as_millis() as u32,
        connection_info: format!("{}:{}", remote_addr.ip(), remote_addr.port()),
    };

    if let Err(e) = storage.record_connection(record) {
        tracing::error!("Failed to record honeypot connection: {}", e);
    }

    tracing::debug!(
        "Honeypot connection: {}:{} -> {} ({}), {} bytes, {}ms",
        remote_addr.ip(),
        remote_addr.port(),
        local_port,
        service,
        bytes_read,
        duration.as_millis()
    );
}
