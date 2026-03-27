use std::net::SocketAddr;
use std::sync::atomic::{AtomicI64, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use tokio::net::{UdpSocket, UnixDatagram};
use tokio::sync::broadcast;

use dashmap::DashMap;
use metrics::{counter, gauge, histogram};
use parking_lot::RwLock as PLRwLock;
use std::sync::LazyLock;

#[cfg(unix)]
use socket2::{Domain, Protocol, Socket, Type};

use crate::buffer::BufferPool;
use crate::metrics::bandwidth::{
    get_global_bandwidth_tracker_or_log, BandwidthProtocol, EgressDirection,
};
use crate::tunnel;
use crate::tunnel::quic::messages::TunnelMessage;
use crate::tunnel::udp_manager::{UdpTunnelConfig, UdpTunnelManager};
use crate::udp::filter::{UdpFilterAction, UdpFilterConfig, UdpProtocolFilter};
use crate::udp::protocol::UdpProtocolDetector;
use crate::upstream::UpstreamAddress;
use crate::waf::FloodProtector;

static UDP_TUNNEL_MANAGER: LazyLock<parking_lot::RwLock<Option<Arc<UdpTunnelManager>>>> =
    LazyLock::new(|| parking_lot::RwLock::new(None));

pub fn init_udp_tunnel_manager(config: UdpTunnelConfig) {
    let manager = Arc::new(UdpTunnelManager::new(config));
    let mut guard = UDP_TUNNEL_MANAGER.write();
    *guard = Some(manager);
}

pub fn get_udp_tunnel_manager() -> Option<Arc<UdpTunnelManager>> {
    let guard = UDP_TUNNEL_MANAGER.read();
    guard.clone()
}

const SHARD_COUNT: usize = 64;

#[derive(Debug, Clone)]
pub struct UdpSocketOptions {
    pub reuse_port: bool,
    pub recv_buffer_size: usize,
    pub send_buffer_size: usize,
}

impl Default for UdpSocketOptions {
    fn default() -> Self {
        Self {
            reuse_port: true,
            recv_buffer_size: 2 * 1024 * 1024,
            send_buffer_size: 2 * 1024 * 1024,
        }
    }
}

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
    pub socket_options: UdpSocketOptions,
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
            socket_options: UdpSocketOptions::default(),
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
    socket_options: UdpSocketOptions,
}

#[derive(Debug, Clone)]
pub struct UdpListenerPoolConfig {
    pub worker_pool_size: usize,
    pub buffer_size: usize,
    pub max_packets_per_second: u32,
    pub socket_options: UdpSocketOptions,
    pub workers_per_listener: usize,
}

impl Default for UdpListenerPoolConfig {
    fn default() -> Self {
        Self {
            worker_pool_size: 4,
            buffer_size: 8192,
            max_packets_per_second: 10000,
            socket_options: UdpSocketOptions::default(),
            workers_per_listener: 1,
        }
    }
}

#[derive(Debug, Clone)]
struct UdpListenerInstance {
    config: UdpListenerConfig,
    #[allow(dead_code)] // Retained for logging and debugging
    listen_addr: SocketAddr,
}

impl UdpListenerPool {
    pub fn new(pool_config: UdpListenerPoolConfig, filter_config: UdpFilterConfig) -> Self {
        let (shutdown_tx, _) = broadcast::channel(1);
        let socket_options = pool_config.socket_options.clone();

        Self {
            config: pool_config,
            listeners: Arc::new(PLRwLock::new(Vec::new())),
            shutdown_tx,
            protocol_detector: UdpProtocolDetector::new(),
            protocol_filter: UdpProtocolFilter::new(filter_config),
            flood_protector: None,
            socket_options,
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
        let workers_per_listener = self.config.workers_per_listener;
        let socket_options = self.socket_options.clone();

        for instance in listeners {
            for worker_id in 0..workers_per_listener {
                let config = instance.config.clone();
                let shutdown_rx = self.shutdown_tx.subscribe();
                let detector = self.protocol_detector.clone();
                let filter = self.protocol_filter.clone();
                let flood_protector = self.flood_protector.clone();
                let buffer_size = self.config.buffer_size;
                let sock_opts = socket_options.clone();

                tokio::spawn(async move {
                    Self::listen_loop(
                        config,
                        shutdown_rx,
                        detector,
                        filter,
                        flood_protector,
                        buffer_size,
                        sock_opts,
                        worker_id,
                    )
                    .await;
                });
            }
        }

        tracing::info!(
            "UDP listener pool started with {} listeners x {} workers = {} total workers",
            listener_count,
            workers_per_listener,
            listener_count * workers_per_listener
        );
    }

    async fn listen_loop(
        config: UdpListenerConfig,
        mut shutdown_rx: broadcast::Receiver<()>,
        detector: UdpProtocolDetector,
        filter: UdpProtocolFilter,
        flood_protector: Option<Arc<FloodProtector>>,
        buffer_size: usize,
        socket_options: UdpSocketOptions,
        worker_id: usize,
    ) {
        let bind_addr = format!("{}:{}", config.bind_address, config.port);

        #[cfg(unix)]
        let socket = {
            let addr: SocketAddr = match bind_addr.parse() {
                Ok(a) => a,
                Err(e) => {
                    tracing::error!("Failed to parse bind address {}: {}", bind_addr, e);
                    return;
                }
            };

            let domain = if addr.is_ipv6() {
                Domain::IPV6
            } else {
                Domain::IPV4
            };

            let sock = match Socket::new(domain, Type::DGRAM, Some(Protocol::UDP)) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("Failed to create UDP socket for {}: {}", bind_addr, e);
                    return;
                }
            };

            sock.set_reuse_address(true).ok();

            if socket_options.reuse_port {
                #[cfg(target_os = "linux")]
                sock.set_reuse_port(true).ok();
            }

            sock.set_nonblocking(true).ok();

            let _ = sock.set_recv_buffer_size(socket_options.recv_buffer_size);
            let _ = sock.set_send_buffer_size(socket_options.send_buffer_size);

            if let Err(e) = sock.bind(&addr.into()) {
                tracing::error!("Failed to bind UDP socket to {}: {}", bind_addr, e);
                return;
            }

            let std_socket: std::net::UdpSocket = sock.into();
            match UdpSocket::from_std(std_socket) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!(
                        "Failed to convert to tokio UDP socket for {}: {}",
                        bind_addr,
                        e
                    );
                    return;
                }
            }
        };

        #[cfg(not(unix))]
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
                tracing::error!(
                    "Invalid upstream address {}: {}",
                    config.upstream_address,
                    e
                );
                return;
            }
        };

        let _upstream_unix_socket: Option<UnixDatagram> = match &upstream_addr {
            UpstreamAddress::Tcp(_) => None,
            UpstreamAddress::Unix(path) => match std::os::unix::net::UnixDatagram::bind(path) {
                Ok(s) => Some(UnixDatagram::from_std(s).ok()).flatten(),
                Err(e) => {
                    tracing::error!("Failed to bind Unix socket {}: {}", path.display(), e);
                    None
                }
            },
            UpstreamAddress::QuicTunnel { .. } => None,
        };

        let tcp_upstream_socket: Option<UdpSocket> = match upstream_addr {
            UpstreamAddress::Tcp(_) => match UdpSocket::bind("0.0.0.0:0").await {
                Ok(s) => Some(s),
                Err(e) => {
                    tracing::error!("Failed to bind upstream UDP socket: {}", e);
                    None
                }
            },
            UpstreamAddress::Unix(_) => None,
            UpstreamAddress::QuicTunnel { .. } => None,
        };

        tracing::info!(
            "UDP listener running on {} for protocol {} (worker {})",
            bind_addr,
            config.expected_protocol,
            worker_id
        );

        let mut pooled_buf = BufferPool::acquire(buffer_size);
        let rate_limiter = UdpRateLimiter::new(config.rate_limit_per_ip);
        let mut cleanup_counter: u32 = 0;

        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    tracing::info!("UDP listener shutting down on {}", bind_addr);
                    break;
                }
                result = socket.recv_from(pooled_buf.as_mut_slice()) => {
                    match result {
                        Ok((n, client_addr)) => {
                            let bandwidth = get_global_bandwidth_tracker_or_log();
                            if let Some(ref bw) = bandwidth {
                                bw.record_ingress(n as u64, BandwidthProtocol::Udp);
                            }

                            let start = std::time::Instant::now();
                            let client_ip = client_addr.ip();
                            let data = &pooled_buf.as_slice()[..n];

                            cleanup_counter = cleanup_counter.wrapping_add(1);
                            if cleanup_counter.is_multiple_of(1000) {
                                rate_limiter.cleanup_stale(60);
                            }

                            if let Some(ref fp) = flood_protector {
                                use crate::waf::FloodDecision;
                                match fp.check_udp(client_ip) {
                                    FloodDecision::Blackholed => {
                                        counter!("maluwaf.udp.flood_blackhole").increment(1);
                                        continue;
                                    }
                                    FloodDecision::RateLimited => {
                                        counter!("maluwaf.udp.flood_limited").increment(1);
                                        continue;
                                    }
                                    FloodDecision::Allowed => {}
                                }
                            }

                            if !rate_limiter.check(client_ip) {
                                counter!("maluwaf.udp.rate_limited").increment(1);
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
                                        counter!("maluwaf.udp.protocol_rejected").increment(1);
                                        histogram!("maluwaf.udp.packet_duration").record(start.elapsed());
                                        continue;
                                    }
                                    UdpFilterAction::RateLimit { rate } => {
                                        if rate_limiter.check_with_limit(client_ip, rate) {
                                            counter!("maluwaf.udp.protocol_rate_limited").increment(1);
                                            continue;
                                        }
                                    }
                                    UdpFilterAction::Allow => {
                                        counter!("maluwaf.udp.protocol_allowed").increment(1);
                                    }
                                    UdpFilterAction::Challenge => {
                                        counter!("maluwaf.udp.protocol_challenged").increment(1);
                                        continue;
                                    }
                                }
                            }

                            if n > config.max_packet_size {
                                counter!("maluwaf.udp.oversized_packet").increment(1);
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
                                    let data_owned = data.to_vec();
                                    let path_owned = path.clone();
                                    tokio::task::spawn_blocking(move || {
                                        match std::os::unix::net::UnixDatagram::unbound() {
                                            Ok(socket) => socket.send_to(&data_owned, &path_owned),
                                            Err(e) => Err(e),
                                        }
                                    }).await.unwrap_or_else(|e| {
                                        Err(std::io::Error::other(e.to_string()))
                                    })
                                }
                                UpstreamAddress::QuicTunnel { peer, port } => {
                                    match get_udp_tunnel_manager() {
                                        Some(manager) => {
                                            match manager.send(peer, *port, data, client_addr).await {
                                                Ok(_) => {
                                                    counter!("maluwaf.udp.quic_tunnel.packets_sent").increment(1);
                                                    counter!("maluwaf.udp.quic_tunnel.datagram_used").increment(1);
                                                    Ok(n)
                                                }
                                                Err(e) => {
                                                    Err(std::io::Error::new(
                                                        std::io::ErrorKind::NotConnected,
                                                        format!("Failed to send via UDP tunnel manager: {}", e)
                                                    ))
                                                }
                                            }
                                        }
                                        None => {
                                            let registry = tunnel::QUIC_TUNNEL_REGISTRY.clone();
                                            match registry.get_runtime().await {
                                                Some(runtime) => {
                                                    let identifier = format!("udp-port-{}", port);

                                                    match runtime.open_tunnel_stream_to_peer(peer, &identifier).await {
                                                        Ok((mut send_stream, _recv_stream)) => {
                                                            match TunnelMessage::write_data_chunk_zero_copy(
                                                                &mut send_stream,
                                                                &identifier,
                                                                0,
                                                                data,
                                                                false,
                                                            ).await {
                                                                Ok(_) => {
                                                                    counter!("maluwaf.udp.quic_tunnel.packets_sent").increment(1);
                                                                    counter!("maluwaf.udp.quic_tunnel.stream_fallback").increment(1);
                                                                    Ok(n)
                                                                }
                                                                Err(e) => {
                                                                    Err(std::io::Error::new(
                                                                        std::io::ErrorKind::InvalidData,
                                                                        format!("Zero-copy write error: {}", e)
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
                                    }
                                }
                            };

                            match send_result {
                                Ok(_sent) => {
                                    counter!("maluwaf.udp.packets_forwarded").increment(1);
                                    gauge!("maluwaf.udp.packet_size").set(n as f64);

                                    let upstream_str = match &upstream_addr {
                                        UpstreamAddress::Tcp(addr) => addr.to_string(),
                                        UpstreamAddress::Unix(path) => path.to_string_lossy().to_string(),
                                        UpstreamAddress::QuicTunnel { peer, port } => format!("{}:{}", peer, port),
                                    };
                                    if let Some(ref bw) = bandwidth {
                                        bw.record_proxied(n as u64, 0, &upstream_str);
                                        bw.record_egress(n as u64, BandwidthProtocol::Udp, EgressDirection::Proxied);
                                    }
                                }
                                Err(e) => {
                                    tracing::debug!("Failed to forward UDP packet: {}", e);
                                    counter!("maluwaf.udp.forward_error").increment(1);
                                }
                            }

                            histogram!("maluwaf.udp.packet_duration").record(start.elapsed());
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
    shards: [DashMap<std::net::IpAddr, RateEntry>; SHARD_COUNT],
    total_tracked: AtomicU64,
}

#[derive(Debug)]
struct RateEntry {
    count: AtomicU32,
    window_start: AtomicI64,
}

impl RateEntry {
    fn new() -> Self {
        Self {
            count: AtomicU32::new(1),
            window_start: AtomicI64::new(
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs() as i64,
            ),
        }
    }
}

fn hash_ip(ip: &std::net::IpAddr) -> usize {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    let mut hasher = DefaultHasher::new();
    ip.hash(&mut hasher);
    (hasher.finish() as usize) % SHARD_COUNT
}

impl UdpRateLimiter {
    fn new(limit: u32) -> Self {
        Self {
            limit,
            shards: std::array::from_fn(|_| DashMap::new()),
            total_tracked: AtomicU64::new(0),
        }
    }

    fn check(&self, ip: std::net::IpAddr) -> bool {
        self.check_with_limit(ip, self.limit)
    }

    fn check_with_limit(&self, ip: std::net::IpAddr, limit: u32) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let window_secs: i64 = 1;
        let shard_idx = hash_ip(&ip);
        let shard = &self.shards[shard_idx];

        match shard.get(&ip) {
            Some(entry) => {
                let window_start = entry.window_start.load(Ordering::Relaxed);

                if now - window_start >= window_secs {
                    entry.window_start.store(now, Ordering::Relaxed);
                    entry.count.store(1, Ordering::Relaxed);
                    return true;
                }

                let current = entry.count.fetch_add(1, Ordering::Relaxed);
                if current >= limit {
                    entry.count.fetch_sub(1, Ordering::Relaxed);
                    return false;
                }
                true
            }
            _ => {
                shard.insert(ip, RateEntry::new());
                self.total_tracked.fetch_add(1, Ordering::Relaxed);
                true
            }
        }
    }

    fn cleanup_stale(&self, max_age_secs: i64) {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        let mut total_removed = 0u64;
        for shard in &self.shards {
            let before = shard.len() as u64;
            shard.retain(|_, entry| {
                let window_start = entry.window_start.load(Ordering::Relaxed);
                now - window_start < max_age_secs
            });
            total_removed += before - shard.len() as u64;
        }

        if total_removed > 0 {
            self.total_tracked
                .fetch_sub(total_removed, Ordering::Relaxed);
        }
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
