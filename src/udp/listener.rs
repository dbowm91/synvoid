use std::sync::Arc;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::collections::HashMap;
use tokio::net::{UdpSocket, UnixDatagram};
use tokio::sync::broadcast;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use parking_lot::RwLock as PLRwLock;
use metrics::{counter, histogram, gauge};
use quinn::{SendStream, RecvStream};

use crate::udp::protocol::UdpProtocolDetector;
use crate::udp::filter::{UdpProtocolFilter, UdpFilterAction, UdpFilterConfig};
use crate::waf::FloodProtector;
use crate::upstream::UpstreamAddress;
use crate::tunnel;
use crate::tunnel::quic::messages::TunnelMessage;

#[derive(Debug, Clone)]
pub struct UdpListenerConfig {
    pub port: u16,
    pub bind_address: String,
    pub bind_address_v6: Option<String>,
    pub expected_protocol: String,
    pub upstream_address: String,
    pub upstream_address_v6: Option<String>,
    pub filter_enabled: bool,
    pub strict_mode: bool,
    pub max_packet_size: usize,
    pub rate_limit_per_ip: u32,
}

impl Default for UdpListenerConfig {
    fn default() -> Self {
        Self {
            port: 53,
            bind_address: "0.0.0.0".to_string(),
            bind_address_v6: None,
            expected_protocol: "dns".to_string(),
            upstream_address: "127.0.0.1:5353".to_string(),
            upstream_address_v6: Some("[::1]:5353".to_string()),
            filter_enabled: true,
            strict_mode: true,
            max_packet_size: 4096,
            rate_limit_per_ip: 100,
        }
    }
}

#[derive(Clone)]
pub struct UdpListenerPool {
    config: UdpListenerPoolConfig,
    listeners: Arc<PLRwLock<Vec<UdpListenerInstance>>>,
    shutdown_tx: broadcast::Sender<()>,
    protocol_detector: UdpProtocolDetector,
    protocol_filter: UdpProtocolFilter,
    flood_protector: Option<Arc<FloodProtector>>,
}

#[derive(Debug, Clone)]
pub struct UdpListenerPoolConfig {
    pub worker_pool_size: usize,
    pub buffer_size: usize,
    pub max_packets_per_second: u32,
}

impl Default for UdpListenerPoolConfig {
    fn default() -> Self {
        Self {
            worker_pool_size: 4,
            buffer_size: 8192,
            max_packets_per_second: 10000,
        }
    }
}

#[derive(Debug, Clone)]
struct UdpListenerInstance {
    config: UdpListenerConfig,
    listen_addr: SocketAddr,
}

impl UdpListenerPool {
    pub fn new(pool_config: UdpListenerPoolConfig, filter_config: UdpFilterConfig) -> Self {
        let (shutdown_tx, _) = broadcast::channel(1);

        Self {
            config: pool_config,
            listeners: Arc::new(PLRwLock::new(Vec::new())),
            shutdown_tx,
            protocol_detector: UdpProtocolDetector::new(),
            protocol_filter: UdpProtocolFilter::new(filter_config),
            flood_protector: None,
        }
    }

    pub fn with_flood_protector(mut self, flood_protector: Arc<FloodProtector>) -> Self {
        self.flood_protector = Some(flood_protector);
        self
    }

    pub async fn add_listener(
        &self,
        listener_config: UdpListenerConfig,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let bind_addr = format!("{}:{}", listener_config.bind_address, listener_config.port);
        let socket = UdpSocket::bind(&bind_addr).await?;
        let local_addr = socket.local_addr()?;

        tracing::info!(
            "UDP listener bound to {} for protocol {}",
            local_addr,
            listener_config.expected_protocol
        );

        let instance = UdpListenerInstance {
            config: listener_config,
            listen_addr: local_addr,
        };

        self.listeners.write().push(instance);

        Ok(())
    }

    pub async fn start(&self) {
        let listeners = self.listeners.read().clone();
        let listener_count = listeners.len();

        for instance in listeners {
            let config = instance.config.clone();
            let shutdown_rx = self.shutdown_tx.subscribe();
            let detector = self.protocol_detector.clone();
            let filter = self.protocol_filter.clone();
            let flood_protector = self.flood_protector.clone();
            let buffer_size = self.config.buffer_size;

            tokio::spawn(async move {
                Self::listen_loop(
                    config,
                    shutdown_rx,
                    detector,
                    filter,
                    flood_protector,
                    buffer_size,
                )
                .await;
            });
        }

        tracing::info!(
            "UDP listener pool started with {} listeners",
            listener_count
        );
    }

    async fn listen_loop(
        config: UdpListenerConfig,
        mut shutdown_rx: broadcast::Receiver<()>,
        detector: UdpProtocolDetector,
        filter: UdpProtocolFilter,
        flood_protector: Option<Arc<FloodProtector>>,
        buffer_size: usize,
    ) {
        let bind_addr = format!("{}:{}", config.bind_address, config.port);
        let socket = match UdpSocket::bind(&bind_addr).await {
            Ok(s) => s,
            Err(e) => {
                tracing::error!("Failed to bind UDP listener on {}: {}", bind_addr, e);
                return;
            }
        };

        let upstream_addr = match UpstreamAddress::parse(&config.upstream_address) {
            Ok(addr) => addr,
            Err(e) => {
                tracing::error!("Invalid upstream address {}: {}", config.upstream_address, e);
                return;
            }
        };

        let upstream_unix_socket: Option<UnixDatagram> = match &upstream_addr {
            UpstreamAddress::Tcp(_) => None,
            UpstreamAddress::Unix(path) => {
                match std::os::unix::net::UnixDatagram::bind(path) {
                    Ok(s) => Some(UnixDatagram::from_std(s).ok()).flatten(),
                    Err(e) => {
                        tracing::error!("Failed to bind Unix socket {}: {}", path.display(), e);
                        None
                    }
                }
            }
            UpstreamAddress::QuicTunnel { .. } => None,
        };

        let tcp_upstream_socket: Option<UdpSocket> = match upstream_addr {
            UpstreamAddress::Tcp(_) => {
                match UdpSocket::bind("0.0.0.0:0").await {
                    Ok(s) => Some(s),
                    Err(e) => {
                        tracing::error!("Failed to bind upstream UDP socket: {}", e);
                        None
                    }
                }
            }
            UpstreamAddress::Unix(_) => None,
            UpstreamAddress::QuicTunnel { .. } => None,
        };

        tracing::info!(
            "UDP listener running on {} for protocol {}",
            bind_addr,
            config.expected_protocol
        );

        let mut buf = vec![0u8; buffer_size];
        let rate_limiter = UdpRateLimiter::new(config.rate_limit_per_ip);

        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    tracing::info!("UDP listener shutting down on {}", bind_addr);
                    break;
                }
                result = socket.recv_from(&mut buf) => {
                    match result {
                        Ok((n, client_addr)) => {
                            let start = std::time::Instant::now();
                            let client_ip = client_addr.ip();
                            let data = &buf[..n];

                            if let Some(ref fp) = flood_protector {
                                use crate::waf::FloodDecision;
                                match fp.check_udp(client_ip) {
                                    FloodDecision::Blackholed => {
                                        counter!("rustwaf.udp.flood_blackhole").increment(1);
                                        continue;
                                    }
                                    FloodDecision::RateLimited => {
                                        counter!("rustwaf.udp.flood_limited").increment(1);
                                        continue;
                                    }
                                    FloodDecision::Allowed => {}
                                }
                            }

                            if !rate_limiter.check(client_ip) {
                                counter!("rustwaf.udp.rate_limited").increment(1);
                                continue;
                            }

                            if config.filter_enabled {
                                let detection_result = detector.detect_from_bytes(data);
                                let action = filter.check(&config.expected_protocol, &detection_result.protocol);

                                match action {
                                    UdpFilterAction::Drop => {
                                        tracing::debug!(
                                            "UDP protocol mismatch on port {}: expected {} but detected {} from {}",
                                            config.port,
                                            config.expected_protocol,
                                            detection_result.protocol.as_str(),
                                            client_addr
                                        );
                                        counter!("rustwaf.udp.protocol_rejected").increment(1);
                                        histogram!("rustwaf.udp.packet_duration").record(start.elapsed());
                                        continue;
                                    }
                                    UdpFilterAction::RateLimit { rate } => {
                                        if rate_limiter.check_with_limit(client_ip, rate) {
                                            counter!("rustwaf.udp.protocol_rate_limited").increment(1);
                                            continue;
                                        }
                                    }
                                    UdpFilterAction::Allow => {
                                        counter!("rustwaf.udp.protocol_allowed").increment(1);
                                    }
                                    UdpFilterAction::Challenge => {
                                        counter!("rustwaf.udp.protocol_challenged").increment(1);
                                        continue;
                                    }
                                }
                            }

                            if n > config.max_packet_size {
                                counter!("rustwaf.udp.oversized_packet").increment(1);
                                continue;
                            }

                            let send_result: Result<usize, std::io::Error> = match &upstream_addr {
                                UpstreamAddress::Tcp(addr) => {
                                    if let Some(ref socket) = tcp_upstream_socket {
                                        socket.send_to(data, *addr).await
                                    } else {
                                        Err(std::io::Error::new(
                                            std::io::ErrorKind::NotConnected,
                                            "TCP upstream socket not available"
                                        ))
                                    }
                                }
                                UpstreamAddress::Unix(path) => {
                                    if let Some(ref _socket) = upstream_unix_socket {
                                        let data_owned = data.to_vec();
                                        let path_owned = path.clone();
                                        tokio::task::spawn_blocking(move || {
                                            match std::os::unix::net::UnixDatagram::bind(&path_owned) {
                                                Ok(socket) => socket.send_to(&data_owned, &path_owned),
                                                Err(e) => Err(e),
                                            }
                                        }).await.unwrap_or_else(|e| {
                                            Err(std::io::Error::new(std::io::ErrorKind::Other, e.to_string()))
                                        })
                                    } else {
                                        Err(std::io::Error::new(
                                            std::io::ErrorKind::NotFound,
                                            format!("Unix socket not found: {}", path.display())
                                        ))
                                    }
                                }
                                UpstreamAddress::QuicTunnel { peer, port } => {
                                    let registry = tunnel::QUIC_TUNNEL_REGISTRY.clone();
                                    match registry.get_runtime().await {
                                        Some(runtime) => {
                                            let identifier = format!("udp-port-{}", port);
                                            
                                            match runtime.open_tunnel_stream_to_peer(peer, &identifier).await {
                                                Ok((mut send_stream, _recv_stream)) => {
                                                    let data_msg = TunnelMessage::DataChunk {
                                                        identifier: identifier.clone(),
                                                        sequence: 0,
                                                        data: data.to_vec(),
                                                        fin: false,
                                                    };
                                                    
                                                    match data_msg.encode() {
                                                        Ok(encoded) => {
                                                            let len = (encoded.len() as u32).to_be_bytes();
                                                            let _ = send_stream.write_all(&len).await;
                                                            let _ = send_stream.write_all(&encoded).await;
                                                            counter!("rustwaf.udp.quic_tunnel.packets_sent").increment(1);
                                                            Ok(data.len())
                                                        }
                                                        Err(e) => {
                                                            Err(std::io::Error::new(
                                                                std::io::ErrorKind::InvalidData,
                                                                format!("Encode error: {}", e)
                                                            ))
                                                        }
                                                    }
                                                }
                                                Err(e) => {
                                                    Err(std::io::Error::new(
                                                        std::io::ErrorKind::NotConnected,
                                                        format!("Failed to open QUIC stream: {}", e)
                                                    ))
                                                }
                                            }
                                        }
                                        None => {
                                            Err(std::io::Error::new(
                                                std::io::ErrorKind::NotConnected,
                                                "QUIC tunnel runtime not available"
                                            ))
                                        }
                                    }
                                }
                            };

                            match send_result {
                                Ok(sent) => {
                                    counter!("rustwaf.udp.packets_forwarded").increment(1);
                                    gauge!("rustwaf.udp.packet_size").set(n as f64);
                                }
                                Err(e) => {
                                    tracing::debug!("Failed to forward UDP packet: {}", e);
                                    counter!("rustwaf.udp.forward_error").increment(1);
                                }
                            }

                            histogram!("rustwaf.udp.packet_duration").record(start.elapsed());
                        }
                        Err(e) => {
                            tracing::error!("UDP recv error: {}", e);
                        }
                    }
                }
            }
        }
    }

    pub async fn shutdown(&self) {
        let _ = self.shutdown_tx.send(());
        tracing::info!("UDP listener pool shutdown initiated");
    }

    pub fn listener_count(&self) -> usize {
        self.listeners.read().len()
    }
}

struct UdpRateLimiter {
    limit: u32,
    trackers: Arc<PLRwLock<Vec<(std::net::IpAddr, u32, std::time::Instant)>>>,
}

impl UdpRateLimiter {
    fn new(limit: u32) -> Self {
        Self {
            limit,
            trackers: Arc::new(PLRwLock::new(Vec::new())),
        }
    }

    fn check(&self, ip: std::net::IpAddr) -> bool {
        self.check_with_limit(ip, self.limit)
    }

    fn check_with_limit(&self, ip: std::net::IpAddr, limit: u32) -> bool {
        let mut trackers = self.trackers.write();
        let now = std::time::Instant::now();
        let window = std::time::Duration::from_secs(1);

        trackers.retain(|(_, _, ts)| now.duration_since(*ts) < window);

        for entry in trackers.iter_mut() {
            if entry.0 == ip {
                if entry.1 >= limit {
                    return false;
                }
                entry.1 += 1;
                return true;
            }
        }

        trackers.push((ip, 1, now));
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_udp_rate_limiter() {
        let limiter = UdpRateLimiter::new(5);
        let ip = std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 168, 1, 1));

        for i in 0..5 {
            assert!(limiter.check(ip), "Packet {} should be allowed", i);
        }

        assert!(!limiter.check(ip), "Packet 6 should be rate limited");
    }

    #[test]
    fn test_udp_config_default() {
        let config = UdpListenerConfig::default();
        assert_eq!(config.port, 53);
        assert_eq!(config.expected_protocol, "dns");
        assert!(config.filter_enabled);
    }
}
