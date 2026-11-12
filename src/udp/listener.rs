use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicI64, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use dashmap::DashMap;
use metrics::{counter, gauge, histogram};
use parking_lot::RwLock as PLRwLock;
use tokio::net::{UdpSocket, UnixDatagram};
use tokio::sync::broadcast;

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

fn format_bind_address(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
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
    pub max_flows: usize,
    pub flow_idle_timeout_secs: u64,
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
            max_flows: 4096,
            flow_idle_timeout_secs: 60,
        }
    }
}

#[derive(Clone)]
pub struct UdpListenerPool {
    config: UdpListenerPoolConfig,
    registered: Arc<PLRwLock<Vec<RegisteredUdpListener>>>,
    bound: Arc<PLRwLock<Vec<BoundUdpListener>>>,
    shutdown_tx: broadcast::Sender<()>,
    protocol_detector: UdpProtocolDetector,
    flood_protector: Option<Arc<FloodProtector>>,
    socket_options: UdpSocketOptions,
}

#[derive(Debug, Clone)]
pub struct UdpListenerPoolConfig {
    /// Number of concurrent receive loops per listener. Each loop shares the
    /// listener's `Arc<UdpSocket>` and bounded flow map.
    pub worker_pool_size: usize,
    pub buffer_size: usize,
    pub socket_options: UdpSocketOptions,
}

impl Default for UdpListenerPoolConfig {
    fn default() -> Self {
        Self {
            worker_pool_size: 4,
            buffer_size: 8192,
            socket_options: UdpSocketOptions::default(),
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("failed to bind UDP listener {address}: {source}")]
pub struct UdpListenerBindError {
    pub address: String,
    #[source]
    pub source: std::io::Error,
}

#[derive(Debug, Clone)]
struct RegisteredUdpListener {
    config: UdpListenerConfig,
    active_flows: Arc<AtomicUsize>,
}

#[derive(Debug, Clone)]
struct BoundUdpListener {
    registered: RegisteredUdpListener,
    socket: Arc<UdpSocket>,
    upstream: UpstreamAddress,
    local_addr: SocketAddr,
}

#[derive(Debug, Clone, Hash, PartialEq, Eq)]
enum FlowKey {
    Udp {
        client: SocketAddr,
        upstream: SocketAddr,
    },
    Unix {
        client: SocketAddr,
        path: PathBuf,
    },
}

enum FlowUpstream {
    Udp(Arc<UdpSocket>),
    Unix(Arc<UnixDatagram>),
}

struct UdpFlow {
    upstream: FlowUpstream,
    last_activity: AtomicI64,
}

impl UdpFlow {
    fn touch(&self) {
        self.last_activity.store(now_secs(), Ordering::Relaxed);
    }

    fn idle_for(&self) -> i64 {
        now_secs().saturating_sub(self.last_activity.load(Ordering::Relaxed))
    }
}

fn now_secs() -> i64 {
    i64::try_from(crate::utils::safe_unix_timestamp()).unwrap_or(i64::MAX)
}

/// Process-local view of the bound UDP listeners, used by the admin API.
#[derive(Debug, Clone)]
pub struct UdpListenerSnapshot {
    pub protocol: String,
    pub bind_address: String,
    pub port: u16,
    pub upstream: String,
    pub bound: bool,
    pub workers: usize,
    pub active_flows: usize,
}

struct UdpRegistryEntry {
    snapshot: UdpListenerSnapshot,
    flows: Arc<DashMap<FlowKey, Arc<UdpFlow>>>,
}

static UDP_LISTENER_REGISTRY: LazyLock<PLRwLock<Vec<UdpRegistryEntry>>> =
    LazyLock::new(|| PLRwLock::new(Vec::new()));

pub fn udp_listener_snapshots() -> Vec<UdpListenerSnapshot> {
    UDP_LISTENER_REGISTRY
        .read()
        .iter()
        .map(|entry| {
            let mut snapshot = entry.snapshot.clone();
            snapshot.active_flows = entry.flows.len();
            snapshot
        })
        .collect()
}

impl UdpListenerPool {
    pub fn new(pool_config: UdpListenerPoolConfig) -> Self {
        let (shutdown_tx, _) = broadcast::channel(1);
        let socket_options = pool_config.socket_options.clone();

        Self {
            config: pool_config,
            registered: Arc::new(PLRwLock::new(Vec::new())),
            bound: Arc::new(PLRwLock::new(Vec::new())),
            shutdown_tx,
            protocol_detector: UdpProtocolDetector::new(),
            flood_protector: None,
            socket_options,
        }
    }

    pub fn with_flood_protector(mut self, flood_protector: Arc<FloodProtector>) -> Self {
        self.flood_protector = Some(flood_protector);
        self
    }

    /// Register a listener definition. No socket is opened here.
    pub fn add_listener(&self, listener_config: UdpListenerConfig) {
        self.registered.write().push(RegisteredUdpListener {
            config: listener_config,
            active_flows: Arc::new(AtomicUsize::new(0)),
        });
    }

    /// Bind every registered listener exactly once.
    pub async fn bind_all(&self) -> Result<(), UdpListenerBindError> {
        if !self.bound.read().is_empty() {
            return Ok(());
        }

        let registered = self.registered.read().clone();
        let mut bound = Vec::with_capacity(registered.len());
        let mut registry_entries = Vec::with_capacity(registered.len());
        let workers = self.config.worker_pool_size.max(1);

        for entry in registered {
            let bind_addr = format_bind_address(&entry.config.bind_address, entry.config.port);

            #[cfg(unix)]
            let socket = {
                let addr: SocketAddr =
                    bind_addr
                        .parse::<SocketAddr>()
                        .map_err(|e| UdpListenerBindError {
                            address: bind_addr.clone(),
                            source: std::io::Error::new(
                                std::io::ErrorKind::InvalidInput,
                                e.to_string(),
                            ),
                        })?;

                let domain = if addr.is_ipv6() {
                    Domain::IPV6
                } else {
                    Domain::IPV4
                };
                let sock = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP)).map_err(|e| {
                    UdpListenerBindError {
                        address: bind_addr.clone(),
                        source: e,
                    }
                })?;
                sock.set_reuse_address(true).ok();
                if self.socket_options.reuse_port {
                    #[cfg(target_os = "linux")]
                    sock.set_reuse_port(true).ok();
                }
                sock.set_nonblocking(true)
                    .map_err(|e| UdpListenerBindError {
                        address: bind_addr.clone(),
                        source: e,
                    })?;
                if let Err(e) = sock.set_recv_buffer_size(self.socket_options.recv_buffer_size) {
                    tracing::warn!("Failed to set UDP recv buffer size: {}", e);
                }
                if let Err(e) = sock.set_send_buffer_size(self.socket_options.send_buffer_size) {
                    tracing::warn!("Failed to set UDP send buffer size: {}", e);
                }
                sock.bind(&addr.into()).map_err(|e| UdpListenerBindError {
                    address: bind_addr.clone(),
                    source: e,
                })?;
                let std_socket: std::net::UdpSocket = sock.into();
                UdpSocket::from_std(std_socket).map_err(|e| UdpListenerBindError {
                    address: bind_addr.clone(),
                    source: e,
                })?
            };

            #[cfg(not(unix))]
            let socket = UdpSocket::bind(&bind_addr)
                .await
                .map_err(|e| UdpListenerBindError {
                    address: bind_addr.clone(),
                    source: e,
                })?;

            let local_addr = socket.local_addr().map_err(|e| UdpListenerBindError {
                address: bind_addr.clone(),
                source: e,
            })?;
            let upstream = UpstreamAddress::parse(&entry.config.upstream_address).map_err(|e| {
                UdpListenerBindError {
                    address: bind_addr.clone(),
                    source: std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        format!("invalid upstream '{}': {e}", entry.config.upstream_address),
                    ),
                }
            })?;

            tracing::info!(
                address = %local_addr,
                protocol = %entry.config.expected_protocol,
                upstream = %entry.config.upstream_address,
                workers,
                "UDP listener bound"
            );

            registry_entries.push(UdpRegistryEntry {
                snapshot: UdpListenerSnapshot {
                    protocol: entry.config.expected_protocol.clone(),
                    bind_address: entry.config.bind_address.clone(),
                    port: local_addr.port(),
                    upstream: entry.config.upstream_address.clone(),
                    bound: true,
                    workers,
                    active_flows: 0,
                },
                flows: Arc::new(DashMap::new()),
            });

            bound.push(BoundUdpListener {
                registered: entry,
                socket: Arc::new(socket),
                upstream,
                local_addr,
            });
        }

        *self.bound.write() = bound;
        {
            // Merge into the process-wide inventory; see the TCP pool.
            let mut registry = UDP_LISTENER_REGISTRY.write();
            for entry in registry_entries {
                let existing = registry.iter_mut().find(|current| {
                    current.snapshot.port == entry.snapshot.port
                        && current.snapshot.bind_address == entry.snapshot.bind_address
                        && current.snapshot.protocol == entry.snapshot.protocol
                });
                if let Some(current) = existing {
                    *current = entry;
                } else {
                    registry.push(entry);
                }
            }
        }
        Ok(())
    }

    pub async fn start(&self) {
        if self.bound.read().is_empty() && !self.registered.read().is_empty() {
            if let Err(e) = self.bind_all().await {
                tracing::error!("UDP listener pool failed to bind: {}", e);
                return;
            }
        }

        let bound = self.bound.read().clone();
        let listener_count = bound.len();
        let workers_per_listener = self.config.worker_pool_size.max(1);

        for instance in bound {
            let filter = UdpProtocolFilter::new(UdpFilterConfig {
                enabled: instance.registered.config.filter_enabled,
                strict_mode: instance.registered.config.strict_mode,
                ..Default::default()
            });
            let flows: Arc<DashMap<FlowKey, Arc<UdpFlow>>> = Arc::new(DashMap::new());
            {
                let mut registry = UDP_LISTENER_REGISTRY.write();
                if let Some(entry) = registry.iter_mut().find(|e| {
                    e.snapshot.port == instance.local_addr.port()
                        && e.snapshot.bind_address == instance.registered.config.bind_address
                }) {
                    entry.flows = flows.clone();
                }
            }
            let rate_limiter = Arc::new(UdpRateLimiter::new(
                instance.registered.config.rate_limit_per_ip,
            ));

            let receive_buffer = self
                .config
                .buffer_size
                .max(instance.registered.config.max_packet_size);
            for worker_id in 0..workers_per_listener {
                let config = instance.registered.config.clone();
                let active_flows = instance.registered.active_flows.clone();
                let socket = instance.socket.clone();
                let upstream = instance.upstream.clone();
                let shutdown_rx = self.shutdown_tx.subscribe();
                let detector = self.protocol_detector.clone();
                let filter = filter.clone();
                let flood_protector = self.flood_protector.clone();
                let flows = flows.clone();
                let rate_limiter = rate_limiter.clone();

                tokio::spawn(async move {
                    Self::listen_loop(
                        socket,
                        config,
                        active_flows,
                        worker_id,
                        upstream,
                        shutdown_rx,
                        detector,
                        filter,
                        flood_protector,
                        flows,
                        rate_limiter,
                        receive_buffer,
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

    #[allow(clippy::too_many_arguments)]
    async fn listen_loop(
        socket: Arc<UdpSocket>,
        config: UdpListenerConfig,
        active_flows: Arc<AtomicUsize>,
        worker_id: usize,
        upstream_addr: UpstreamAddress,
        mut shutdown_rx: broadcast::Receiver<()>,
        detector: UdpProtocolDetector,
        filter: UdpProtocolFilter,
        flood_protector: Option<Arc<FloodProtector>>,
        flows: Arc<DashMap<FlowKey, Arc<UdpFlow>>>,
        rate_limiter: Arc<UdpRateLimiter>,
        buffer_size: usize,
    ) {
        let bind_addr = format_bind_address(&config.bind_address, config.port);
        let mut pooled_buf = BufferPool::acquire(buffer_size);
        let mut cleanup_counter: u32 = 0;

        tracing::info!(
            address = %bind_addr,
            protocol = %config.expected_protocol,
            worker = worker_id,
            "UDP listener receive loop running"
        );

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
                                        counter!("synvoid.udp.flood_blackhole").increment(1);
                                        continue;
                                    }
                                    FloodDecision::RateLimited => {
                                        counter!("synvoid.udp.flood_limited").increment(1);
                                        continue;
                                    }
                                    FloodDecision::Allowed => {}
                                }
                            }

                            if !rate_limiter.check(client_ip) {
                                counter!("synvoid.udp.rate_limited").increment(1);
                                continue;
                            }

                            // Enforce the configured maximum before protocol
                            // detection or flow allocation: an oversized
                            // datagram must not consume per-flow resources.
                            if n > config.max_packet_size {
                                counter!("synvoid.udp.oversized_packet").increment(1);
                                continue;
                            }

                            if config.filter_enabled {
                                let detection_result = detector.detect_from_bytes(data);
                                let action =
                                    filter.check(&config.expected_protocol, &detection_result.protocol);

                                match action {
                                    UdpFilterAction::Drop => {
                                        counter!("synvoid.udp.protocol_rejected").increment(1);
                                        continue;
                                    }
                                    UdpFilterAction::RateLimit { rate } => {
                                        if !rate_limiter.check_with_limit(client_ip, rate) {
                                            counter!("synvoid.udp.protocol_rate_limited").increment(1);
                                            continue;
                                        }
                                    }
                                    UdpFilterAction::Allow => {
                                        counter!("synvoid.udp.protocol_allowed").increment(1);
                                    }
                                    UdpFilterAction::Challenge => {
                                        counter!("synvoid.udp.protocol_challenged").increment(1);
                                        continue;
                                    }
                                }
                            }

                            match &upstream_addr {
                                UpstreamAddress::Tcp(upstream) => {
                                    Self::forward_udp_datagram(
                                        data,
                                        n,
                                        client_addr,
                                        *upstream,
                                        &socket,
                                        &config,
                                        &flows,
                                        &active_flows,
                                        bandwidth.as_ref(),
                                    )
                                    .await;
                                }
                                UpstreamAddress::Unix(path) => {
                                    Self::forward_unix_datagram(
                                        data,
                                        n,
                                        client_addr,
                                        path,
                                        &socket,
                                        &config,
                                        &flows,
                                        &active_flows,
                                        bandwidth.as_ref(),
                                    )
                                    .await;
                                }
                                UpstreamAddress::QuicTunnel { peer, port } => {
                                    let send_result = Self::forward_quic_tunnel(
                                        data, peer, *port, client_addr,
                                    )
                                    .await;
                                    match send_result {
                                        Ok(_) => {
                                            counter!("synvoid.udp.packets_forwarded").increment(1);
                                            gauge!("synvoid.udp.packet_size").set(n as f64);
                                            if let Some(ref bw) = bandwidth {
                                                let upstream_str = format!("{}:{}", peer, port);
                                                bw.record_proxied(n as u64, 0, &upstream_str);
                                                bw.record_egress(
                                                    n as u64,
                                                    BandwidthProtocol::Udp,
                                                    EgressDirection::Proxied,
                                                );
                                            }
                                        }
                                        Err(e) => {
                                            tracing::debug!("Failed to forward UDP packet: {}", e);
                                            counter!("synvoid.udp.forward_error").increment(1);
                                        }
                                    }
                                }
                            }

                            histogram!("synvoid.udp.packet_duration").record(start.elapsed());
                        }
                        Err(e) => {
                            tracing::error!("UDP recv error: {}", e);
                        }
                    }
                }
            }
        }

        flows.clear();
    }

    #[allow(clippy::too_many_arguments)]
    async fn forward_udp_datagram(
        data: &[u8],
        n: usize,
        client_addr: SocketAddr,
        upstream_addr: SocketAddr,
        listener_socket: &Arc<UdpSocket>,
        config: &UdpListenerConfig,
        flows: &Arc<DashMap<FlowKey, Arc<UdpFlow>>>,
        active_flows: &Arc<AtomicUsize>,
        bandwidth: Option<&Arc<crate::metrics::bandwidth::BandwidthTracker>>,
    ) {
        let key = FlowKey::Udp {
            client: client_addr,
            upstream: upstream_addr,
        };

        if let Some(flow) = flows.get(&key).map(|f| f.clone()) {
            flow.touch();
            if let FlowUpstream::Udp(socket) = &flow.upstream {
                match socket.send(data).await {
                    Ok(_) => {
                        counter!("synvoid.udp.packets_forwarded").increment(1);
                        gauge!("synvoid.udp.packet_size").set(n as f64);
                        if let Some(bw) = bandwidth {
                            bw.record_proxied(n as u64, 0, &upstream_addr.to_string());
                            bw.record_egress(
                                n as u64,
                                BandwidthProtocol::Udp,
                                EgressDirection::Proxied,
                            );
                        }
                    }
                    Err(e) => {
                        tracing::debug!("Failed to forward UDP packet: {}", e);
                        counter!("synvoid.udp.forward_error").increment(1);
                    }
                }
            }
            return;
        }

        if flows.len() >= config.max_flows {
            counter!("synvoid.udp.flows.rejected").increment(1);
            tracing::debug!(
                client = %client_addr,
                upstream = %upstream_addr,
                "UDP flow cap reached; dropping datagram"
            );
            return;
        }

        let bind_wildcard = if upstream_addr.is_ipv6() {
            "[::]:0"
        } else {
            "0.0.0.0:0"
        };
        let socket = match UdpSocket::bind(bind_wildcard).await {
            Ok(socket) => socket,
            Err(e) => {
                tracing::debug!("Failed to bind UDP upstream socket: {}", e);
                counter!("synvoid.udp.forward_error").increment(1);
                return;
            }
        };
        if let Err(e) = socket.connect(upstream_addr).await {
            tracing::debug!("Failed to connect UDP upstream {}: {}", upstream_addr, e);
            counter!("synvoid.udp.forward_error").increment(1);
            return;
        }
        if let Err(e) = socket.send(data).await {
            tracing::debug!("Failed to forward UDP packet: {}", e);
            counter!("synvoid.udp.forward_error").increment(1);
            return;
        }

        counter!("synvoid.udp.packets_forwarded").increment(1);
        gauge!("synvoid.udp.packet_size").set(n as f64);
        if let Some(bw) = bandwidth {
            bw.record_proxied(n as u64, 0, &upstream_addr.to_string());
            bw.record_egress(n as u64, BandwidthProtocol::Udp, EgressDirection::Proxied);
        }

        let flow = Arc::new(UdpFlow {
            upstream: FlowUpstream::Udp(Arc::new(socket)),
            last_activity: AtomicI64::new(now_secs()),
        });
        flows.insert(key.clone(), flow.clone());
        active_flows.fetch_add(1, Ordering::Relaxed);
        gauge!(
            "synvoid.udp.flows.active",
            "protocol" => config.expected_protocol.clone(),
            "port" => config.port.to_string()
        )
        .set(flows.len() as f64);

        Self::spawn_reply_task(
            listener_socket.clone(),
            client_addr,
            config.port,
            config.expected_protocol.clone(),
            config.flow_idle_timeout_secs.max(1),
            key,
            flow,
            flows.clone(),
            active_flows.clone(),
        );
    }

    #[allow(clippy::too_many_arguments)]
    async fn forward_unix_datagram(
        data: &[u8],
        n: usize,
        client_addr: SocketAddr,
        path: &std::path::Path,
        listener_socket: &Arc<UdpSocket>,
        config: &UdpListenerConfig,
        flows: &Arc<DashMap<FlowKey, Arc<UdpFlow>>>,
        active_flows: &Arc<AtomicUsize>,
        bandwidth: Option<&Arc<crate::metrics::bandwidth::BandwidthTracker>>,
    ) {
        let key = FlowKey::Unix {
            client: client_addr,
            path: path.to_path_buf(),
        };

        if let Some(flow) = flows.get(&key).map(|f| f.clone()) {
            flow.touch();
            if let FlowUpstream::Unix(socket) = &flow.upstream {
                match socket.send(data).await {
                    Ok(_) => {
                        counter!("synvoid.udp.packets_forwarded").increment(1);
                        if let Some(bw) = bandwidth {
                            bw.record_proxied(n as u64, 0, &path.to_string_lossy());
                            bw.record_egress(
                                n as u64,
                                BandwidthProtocol::Udp,
                                EgressDirection::Proxied,
                            );
                        }
                    }
                    Err(e) => {
                        tracing::debug!("Failed to forward Unix datagram: {}", e);
                        counter!("synvoid.udp.forward_error").increment(1);
                    }
                }
            }
            return;
        }

        if flows.len() >= config.max_flows {
            counter!("synvoid.udp.flows.rejected").increment(1);
            return;
        }

        let socket = match UnixDatagram::unbound() {
            Ok(socket) => socket,
            Err(e) => {
                tracing::debug!("Failed to create Unix datagram socket: {}", e);
                counter!("synvoid.udp.forward_error").increment(1);
                return;
            }
        };
        if let Err(e) = socket.connect(path) {
            tracing::warn!(
                "Failed to connect Unix datagram to {}: {}",
                path.display(),
                e
            );
            counter!("synvoid.udp.forward_error").increment(1);
            return;
        }
        if let Err(e) = socket.send(data).await {
            tracing::debug!("Failed to forward Unix datagram: {}", e);
            counter!("synvoid.udp.forward_error").increment(1);
            return;
        }

        counter!("synvoid.udp.packets_forwarded").increment(1);
        let flow = Arc::new(UdpFlow {
            upstream: FlowUpstream::Unix(Arc::new(socket)),
            last_activity: AtomicI64::new(now_secs()),
        });
        flows.insert(key.clone(), flow.clone());
        active_flows.fetch_add(1, Ordering::Relaxed);
        gauge!(
            "synvoid.udp.flows.active",
            "protocol" => config.expected_protocol.clone(),
            "port" => config.port.to_string()
        )
        .set(flows.len() as f64);

        Self::spawn_reply_task(
            listener_socket.clone(),
            client_addr,
            config.port,
            config.expected_protocol.clone(),
            config.flow_idle_timeout_secs.max(1),
            key,
            flow,
            flows.clone(),
            active_flows.clone(),
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn spawn_reply_task(
        listener_socket: Arc<UdpSocket>,
        client_addr: SocketAddr,
        listener_port: u16,
        protocol: String,
        idle_timeout_secs: u64,
        key: FlowKey,
        flow: Arc<UdpFlow>,
        flows: Arc<DashMap<FlowKey, Arc<UdpFlow>>>,
        active_flows: Arc<AtomicUsize>,
    ) {
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65535];
            loop {
                let idle = flow.idle_for();
                if idle >= idle_timeout_secs as i64 {
                    break;
                }
                let remaining = Duration::from_secs((idle_timeout_secs as i64 - idle) as u64);
                let result = tokio::select! {
                    result = async {
                        match &flow.upstream {
                            FlowUpstream::Udp(socket) => socket.recv(&mut buf).await,
                            FlowUpstream::Unix(socket) => socket.recv(&mut buf).await,
                        }
                    } => result,
                    _ = tokio::time::sleep(remaining) => {
                        continue;
                    }
                };

                match result {
                    Ok(n) => {
                        flow.touch();
                        match listener_socket.send_to(&buf[..n], client_addr).await {
                            Ok(_) => {
                                counter!("synvoid.udp.responses_sent").increment(1);
                                gauge!("synvoid.udp.response_size").set(n as f64);
                                if let Some(bw) = get_global_bandwidth_tracker_or_log() {
                                    bw.record_egress(
                                        n as u64,
                                        BandwidthProtocol::Udp,
                                        EgressDirection::Proxied,
                                    );
                                }
                            }
                            Err(e) => {
                                tracing::debug!(
                                    "Failed to send UDP response to {}: {}",
                                    client_addr,
                                    e
                                );
                                counter!(
                                    "synvoid.udp.reply_errors",
                                    "protocol" => protocol.clone(),
                                    "port" => listener_port.to_string()
                                )
                                .increment(1);
                            }
                        }
                    }
                    Err(e) => {
                        tracing::debug!(
                            "Failed to receive UDP upstream response for {}: {}",
                            client_addr,
                            e
                        );
                        counter!(
                            "synvoid.udp.reply_errors",
                            "protocol" => protocol.clone(),
                            "port" => listener_port.to_string()
                        )
                        .increment(1);
                        break;
                    }
                }
            }

            flows.remove(&key);
            active_flows.fetch_sub(1, Ordering::Relaxed);
            counter!(
                "synvoid.udp.flows.reaped",
                "protocol" => protocol.clone(),
                "port" => listener_port.to_string()
            )
            .increment(1);
            gauge!(
                "synvoid.udp.flows.active",
                "protocol" => protocol.clone(),
                "port" => listener_port.to_string()
            )
            .set(flows.len() as f64);
            tracing::debug!(
                port = listener_port,
                protocol = %protocol,
                client = %client_addr,
                "UDP flow reaped"
            );
        });
    }

    async fn forward_quic_tunnel(
        data: &[u8],
        peer: &str,
        port: u16,
        client_addr: SocketAddr,
    ) -> Result<usize, String> {
        if let Some(manager) = get_udp_tunnel_manager() {
            manager
                .send(peer, port, data, client_addr)
                .await
                .map_err(|e| format!("Failed to send via UDP tunnel manager: {e}"))?;
            counter!("synvoid.udp.quic_tunnel.packets_sent").increment(1);
            counter!("synvoid.udp.quic_tunnel.datagram_used").increment(1);
            return Ok(data.len());
        }

        let registry = tunnel::QUIC_TUNNEL_REGISTRY.clone();
        let Some(runtime) = registry.get_runtime().await else {
            return Err("QUIC tunnel runtime not available".to_string());
        };
        let identifier = format!("udp-port-{port}");
        let (mut send_stream, _recv_stream) = runtime
            .open_tunnel_stream_to_peer(peer, &identifier)
            .await
            .map_err(|e| format!("Failed to open QUIC stream: {e}"))?;
        TunnelMessage::write_data_chunk_zero_copy(&mut send_stream, &identifier, 0, data, false)
            .await
            .map_err(|e| format!("Zero-copy write error: {e}"))?;
        counter!("synvoid.udp.quic_tunnel.packets_sent").increment(1);
        counter!("synvoid.udp.quic_tunnel.stream_fallback").increment(1);
        Ok(data.len())
    }

    pub async fn shutdown(&self) {
        let _ = self.shutdown_tx.send(());
        let bound = self.bound.read().clone();
        {
            let mut registry = UDP_LISTENER_REGISTRY.write();
            registry.retain(|entry| {
                !bound.iter().any(|listener| {
                    listener.local_addr.port() == entry.snapshot.port
                        && listener.registered.config.bind_address == entry.snapshot.bind_address
                        && listener.registered.config.expected_protocol == entry.snapshot.protocol
                })
            });
        }
        tracing::info!("UDP listener pool shutdown initiated");
    }

    pub fn listener_count(&self) -> usize {
        self.registered.read().len()
    }

    pub fn bound_addresses(&self) -> Vec<SocketAddr> {
        self.bound.read().iter().map(|b| b.local_addr).collect()
    }

    pub fn active_flow_count(&self) -> usize {
        self.registered
            .read()
            .iter()
            .map(|r| r.active_flows.load(Ordering::Relaxed))
            .sum()
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
            window_start: AtomicI64::new(now_secs()),
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
        let now = now_secs();

        let window_secs: i64 = 1;
        let shard_idx = hash_ip(&ip);
        let shard = &self.shards[shard_idx];

        match shard.get(&ip) {
            Some(entry) => {
                let window_start = entry.window_start.load(Ordering::Relaxed);

                if now < window_start || now.saturating_sub(window_start) >= window_secs {
                    entry.window_start.store(now, Ordering::Relaxed);
                    entry.count.store(1, Ordering::Relaxed);
                    return true;
                }

                let current = entry.count.fetch_add(1, Ordering::Relaxed);
                if current >= limit {
                    let _ = entry
                        .count
                        .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| v.checked_sub(1));
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
        let now = now_secs();

        let mut total_removed = 0u64;
        for shard in &self.shards {
            let before = shard.len() as u64;
            shard.retain(|_, entry| {
                let window_start = entry.window_start.load(Ordering::Relaxed);
                now >= window_start && now.saturating_sub(window_start) < max_age_secs
            });
            total_removed += before - shard.len() as u64;
        }

        if total_removed > 0 {
            let _ = self
                .total_tracked
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |v| {
                    v.checked_sub(total_removed)
                });
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
        assert!(config.max_flows > 0);
    }
}
