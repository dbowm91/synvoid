use metrics::{counter, gauge, histogram};
use parking_lot::RwLock as PLRwLock;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UnixStream};
use tokio::sync::{broadcast, Semaphore};

#[cfg(unix)]
use socket2::{Domain, Protocol, Socket, Type};

use crate::buffer::BufferPool;
use crate::metrics::bandwidth::{
    get_global_bandwidth_tracker_or_log, BandwidthProtocol, EgressDirection,
};
use crate::streaming::bidirectional::copy_bidirectional_native;
use crate::tcp::filter::{FilterAction, ProtocolFilter};
use crate::tcp::protocol::ProtocolDetector;
use crate::tunnel;
use crate::tunnel::quic::messages::TunnelMessage;
use crate::upstream::UpstreamAddress;
use crate::waf::{FloodDecision, FloodProtector, RateLimitResult, RateLimiterManager};

#[derive(Debug, Clone)]
pub struct TcpSocketOptions {
    pub nodelay: bool,
    pub send_buffer_size: usize,
    pub recv_buffer_size: usize,
    pub reuse_port: bool,
    pub quickack: bool,
    pub keepalive_secs: Option<u64>,
    pub keepalive_interval_secs: Option<u64>,
    pub keepalive_retries: Option<u32>,
}

impl Default for TcpSocketOptions {
    fn default() -> Self {
        Self {
            nodelay: true,
            send_buffer_size: 262144,
            recv_buffer_size: 262144,
            reuse_port: true,
            quickack: true,
            keepalive_secs: Some(60),
            keepalive_interval_secs: Some(10),
            keepalive_retries: Some(3),
        }
    }
}

fn apply_tcp_socket_options(stream: &TcpStream, options: &TcpSocketOptions) -> std::io::Result<()> {
    if options.nodelay {
        stream.set_nodelay(true)?;
    }

    #[cfg(unix)]
    {
        if options.quickack {
            #[cfg(target_os = "linux")]
            {
                use socket2::SockRef;
                let sock_ref = SockRef::from(stream);
                let _ = sock_ref.set_quickack(true);
            }
        }

        if let Some(keepalive_secs) = options.keepalive_secs {
            use socket2::SockRef;
            let sock_ref = SockRef::from(stream);
            let mut keepalive = socket2::TcpKeepalive::new()
                .with_time(std::time::Duration::from_secs(keepalive_secs));

            if let Some(interval) = options.keepalive_interval_secs {
                keepalive = keepalive.with_interval(std::time::Duration::from_secs(interval));
            }

            if let Some(retries) = options.keepalive_retries {
                keepalive = keepalive.with_retries(retries);
            }

            let _ = sock_ref.set_tcp_keepalive(&keepalive);
        }
    }

    Ok(())
}

#[cfg(unix)]
fn create_socket_with_options(
    addr: SocketAddr,
    options: &TcpSocketOptions,
) -> std::io::Result<Socket> {
    let domain = if addr.is_ipv6() {
        Domain::IPV6
    } else {
        Domain::IPV4
    };

    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;

    socket.set_reuse_address(true)?;

    if options.reuse_port {
        #[cfg(target_os = "linux")]
        socket.set_reuse_port(true)?;
    }

    socket.set_nonblocking(true)?;

    if let Some(keepalive_secs) = options.keepalive_secs {
        let keepalive =
            socket2::TcpKeepalive::new().with_time(std::time::Duration::from_secs(keepalive_secs));
        let _ = socket.set_tcp_keepalive(&keepalive);
    }

    Ok(socket)
}

#[cfg(not(unix))]
fn create_socket_with_options(
    _addr: SocketAddr,
    _options: &TcpSocketOptions,
) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "Socket options not supported on this platform",
    ))
}

#[derive(Debug, Clone)]
pub struct TcpListenerConfig {
    pub port: u16,
    pub bind_address: String,
    pub bind_address_v6: Option<String>,
    pub expected_protocol: String,
    pub upstream_address: String,
    pub upstream_address_v6: Option<String>,
    pub filter_enabled: bool,
    pub strict_mode: bool,
    pub socket_options: TcpSocketOptions,
}

impl Default for TcpListenerConfig {
    fn default() -> Self {
        Self {
            port: 25,
            bind_address: "0.0.0.0".to_string(),
            bind_address_v6: None,
            expected_protocol: "smtp".to_string(),
            upstream_address: "127.0.0.1:25".to_string(),
            upstream_address_v6: Some("[::1]:25".to_string()),
            filter_enabled: true,
            strict_mode: true,
            socket_options: TcpSocketOptions::default(),
        }
    }
}

#[derive(Clone)]
pub struct TcpListenerPool {
    config: TcpListenerPoolConfig,
    listeners: Arc<PLRwLock<Vec<TcpListenerInstance>>>,
    shutdown_tx: broadcast::Sender<()>,
    protocol_detector: ProtocolDetector,
    protocol_filter: ProtocolFilter,
    rate_limiter: Option<Arc<RateLimiterManager>>,
    flood_protector: Option<Arc<FloodProtector>>,
    socket_options: TcpSocketOptions,
    connection_semaphore: Option<Arc<Semaphore>>,
    buffer_size: usize,
}

#[derive(Debug, Clone)]
pub struct TcpListenerPoolConfig {
    pub worker_pool_size: usize,
    pub connection_timeout_secs: u64,
    pub max_connections: usize,
    pub socket_options: TcpSocketOptions,
    pub buffer_size: usize,
    pub enable_concurrency_limit: bool,
}

impl Default for TcpListenerPoolConfig {
    fn default() -> Self {
        Self {
            worker_pool_size: 4,
            connection_timeout_secs: 5,
            max_connections: 10000,
            socket_options: TcpSocketOptions::default(),
            buffer_size: 64 * 1024,
            enable_concurrency_limit: true,
        }
    }
}

#[derive(Debug, Clone)]
struct TcpListenerInstance {
    config: TcpListenerConfig,
    #[allow(dead_code)]
    listen_addr: SocketAddr,
}

impl TcpListenerPool {
    pub fn new(
        pool_config: TcpListenerPoolConfig,
        filter_config: crate::tcp::filter::FilterConfig,
    ) -> Self {
        let (shutdown_tx, _) = broadcast::channel(1);
        let socket_options = pool_config.socket_options.clone();
        let buffer_size = pool_config.buffer_size;
        let connection_semaphore = if pool_config.enable_concurrency_limit {
            Some(Arc::new(Semaphore::new(pool_config.max_connections)))
        } else {
            None
        };

        Self {
            config: pool_config,
            listeners: Arc::new(PLRwLock::new(Vec::new())),
            shutdown_tx,
            protocol_detector: ProtocolDetector::new(),
            protocol_filter: ProtocolFilter::new(filter_config),
            rate_limiter: None,
            flood_protector: None,
            socket_options,
            connection_semaphore,
            buffer_size,
        }
    }

    pub fn with_rate_limiter(mut self, rate_limiter: Arc<RateLimiterManager>) -> Self {
        self.rate_limiter = Some(rate_limiter);
        self
    }

    pub fn with_flood_protector(mut self, flood_protector: Arc<FloodProtector>) -> Self {
        self.flood_protector = Some(flood_protector);
        self
    }

    pub async fn add_listener(
        &self,
        listener_config: TcpListenerConfig,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let bind_addr = format!("{}:{}", listener_config.bind_address, listener_config.port);
        let listener = TcpListener::bind(&bind_addr).await?;
        let local_addr = listener.local_addr()?;

        tracing::info!(
            "TCP listener bound to {} for protocol {}",
            local_addr,
            listener_config.expected_protocol
        );

        let instance = TcpListenerInstance {
            config: listener_config,
            listen_addr: local_addr,
        };

        self.listeners.write().push(instance);

        Ok(())
    }

    pub async fn start(&self) {
        let listeners = self.listeners.read().clone();
        let listener_count = listeners.len();
        let socket_options = self.socket_options.clone();
        let connection_semaphore = self.connection_semaphore.clone();
        let buffer_size = self.buffer_size;

        gauge!("maluwaf.tcp.pool.max_connections").set(self.config.max_connections as f64);

        for instance in listeners {
            let config = instance.config.clone();
            let shutdown_rx = self.shutdown_tx.subscribe();
            let detector = self.protocol_detector.clone();
            let filter = self.protocol_filter.clone();
            let rate_limiter = self.rate_limiter.clone();
            let flood_protector = self.flood_protector.clone();
            let sock_opts = socket_options.clone();
            let semaphore = connection_semaphore.clone();

            tokio::spawn(async move {
                Self::listen_loop(
                    config,
                    shutdown_rx,
                    detector,
                    filter,
                    rate_limiter,
                    flood_protector,
                    sock_opts,
                    semaphore,
                    buffer_size,
                )
                .await;
            });
        }

        tracing::info!(
            "TCP listener pool started with {} listeners (max_conns: {}, buffer: {}KB)",
            listener_count,
            self.config.max_connections,
            buffer_size / 1024
        );
    }

    async fn listen_loop(
        config: TcpListenerConfig,
        mut shutdown_rx: broadcast::Receiver<()>,
        detector: ProtocolDetector,
        filter: ProtocolFilter,
        rate_limiter: Option<Arc<RateLimiterManager>>,
        flood_protector: Option<Arc<FloodProtector>>,
        socket_options: TcpSocketOptions,
        connection_semaphore: Option<Arc<Semaphore>>,
        buffer_size: usize,
    ) {
        let bind_addr = format!("{}:{}", config.bind_address, config.port);

        #[cfg(unix)]
        let listener = {
            let addr: SocketAddr = match bind_addr.parse() {
                Ok(a) => a,
                Err(e) => {
                    tracing::error!("Failed to parse bind address {}: {}", bind_addr, e);
                    return;
                }
            };

            let socket = match create_socket_with_options(addr, &socket_options) {
                Ok(s) => s,
                Err(e) => {
                    tracing::error!("Failed to create socket for {}: {}", bind_addr, e);
                    return;
                }
            };

            if let Err(e) = socket.bind(&addr.into()) {
                tracing::error!("Failed to bind socket to {}: {}", bind_addr, e);
                return;
            }

            let backlog = 1024;
            if let Err(e) = socket.listen(backlog) {
                tracing::error!("Failed to listen on {}: {}", bind_addr, e);
                return;
            }

            let std_listener: std::net::TcpListener = socket.into();
            match TcpListener::from_std(std_listener) {
                Ok(l) => l,
                Err(e) => {
                    tracing::error!(
                        "Failed to convert to tokio listener for {}: {}",
                        bind_addr,
                        e
                    );
                    return;
                }
            }
        };

        #[cfg(not(unix))]
        let listener = match TcpListener::bind(&bind_addr).await {
            Ok(l) => l,
            Err(e) => {
                tracing::error!("Failed to bind TCP listener on {}: {}", bind_addr, e);
                return;
            }
        };

        tracing::info!(
            "TCP listener running on {} for protocol {}",
            bind_addr,
            config.expected_protocol
        );

        loop {
            tokio::select! {
                _ = shutdown_rx.recv() => {
                    tracing::info!("TCP listener shutting down on {}", bind_addr);
                    break;
                }
                result = listener.accept() => {
                    match result {
                        Ok((stream, client_addr)) => {
                            let client_ip = client_addr.ip();

                            if let Some(ref fp) = flood_protector {
                                match fp.check_tcp_connection(client_ip) {
                                    FloodDecision::Blackholed => {
                                        counter!("maluwaf.tcp.flood_blackhole").increment(1);
                                        continue;
                                    }
                                    FloodDecision::RateLimited => {
                                        counter!("maluwaf.tcp.flood_limited").increment(1);
                                        continue;
                                    }
                                    FloodDecision::Allowed => {}
                                }
                                fp.register_half_open(client_ip);
                            }

                            if let Some(ref rl) = rate_limiter {
                                if rl.is_in_blackhole() {
                                    counter!("maluwaf.tcp.blackhole_drop").increment(1);
                                    continue;
                                }

                                match rl.check_global() {
                                    RateLimitResult::Blackholed => {
                                        counter!("maluwaf.tcp.blackhole_drop").increment(1);
                                        continue;
                                    }
                                    RateLimitResult::Limited { limit_type, .. } => {
                                        tracing::debug!("TCP global rate limited: {}", limit_type);
                                        counter!("maluwaf.tcp.rate_limited").increment(1);
                                        continue;
                                    }
                                    RateLimitResult::Allowed => {}
                                }
                            }

                            let permit = if let Some(ref sem) = connection_semaphore {
                                match sem.clone().try_acquire_owned() {
                                    Ok(p) => Some(p),
                                    Err(_) => {
                                        counter!("maluwaf.tcp.connection_limit_exceeded").increment(1);
                                        continue;
                                    }
                                }
                            } else {
                                None
                            };

                            let config = config.clone();
                            let detector = detector.clone();
                            let filter = filter.clone();
                            let rate_limiter = rate_limiter.clone();
                            let flood_protector = flood_protector.clone();
                            let sock_opts = socket_options.clone();

                            let _ = apply_tcp_socket_options(&stream, &sock_opts);

                            tokio::spawn(async move {
                                let _permit = permit;
                                if let Err(e) = Self::handle_connection(stream, client_addr, &config, &detector, &filter, rate_limiter.as_ref(), flood_protector.as_ref(), &sock_opts, buffer_size).await {
                                    tracing::debug!("Connection handling error: {}", e);
                                }
                            });
                        }
                        Err(e) => {
                            tracing::error!("Accept error: {}", e);
                        }
                    }
                }
            }
        }
    }

    async fn handle_connection(
        mut client_stream: TcpStream,
        client_addr: SocketAddr,
        config: &TcpListenerConfig,
        detector: &ProtocolDetector,
        filter: &ProtocolFilter,
        rate_limiter: Option<&Arc<RateLimiterManager>>,
        flood_protector: Option<&Arc<FloodProtector>>,
        socket_options: &TcpSocketOptions,
        buffer_size: usize,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let start = std::time::Instant::now();
        let client_ip = client_addr.ip();

        if let Some(rl) = rate_limiter {
            match rl.check_rate_limit(client_ip).await {
                RateLimitResult::Limited { limit_type, .. } => {
                    tracing::debug!("TCP rate limited: {} for {}", limit_type, client_ip);
                    counter!("maluwaf.tcp.ip_rate_limited").increment(1);
                    return Ok(());
                }
                RateLimitResult::Blackholed => {
                    counter!("maluwaf.tcp.blackhole_drop").increment(1);
                    return Ok(());
                }
                RateLimitResult::Allowed => {}
            }
        }

        if config.filter_enabled {
            let detection_result = detector.detect_peek(&client_stream).await?;

            let action = filter.check(&config.expected_protocol, &detection_result.protocol);

            match action {
                FilterAction::Drop => {
                    tracing::info!(
                        "Protocol mismatch on port {}: expected {} but detected {} from {}",
                        config.port,
                        config.expected_protocol,
                        detection_result.protocol.as_str(),
                        client_addr
                    );
                    counter!("maluwaf.tcp.protocol_rejected").increment(1);
                    Self::stall_connection(client_stream, socket_options).await;
                    histogram!("maluwaf.tcp.connection_duration").record(start.elapsed());
                    return Ok(());
                }
                FilterAction::Stall => {
                    tracing::info!(
                        "Protocol mismatch on port {}: expected {} but detected {} from {} - stalling",
                        config.port,
                        config.expected_protocol,
                        detection_result.protocol.as_str(),
                        client_addr
                    );
                    counter!("maluwaf.tcp.protocol_stalled").increment(1);
                    Self::stall_connection(client_stream, socket_options).await;
                    histogram!("maluwaf.tcp.connection_duration").record(start.elapsed());
                    return Ok(());
                }
                FilterAction::Allow => {
                    counter!("maluwaf.tcp.protocol_allowed").increment(1);
                }
            }
        }

        if let Some(fp) = flood_protector {
            fp.register_half_open(client_ip);
        }

        let upstream_addr = match UpstreamAddress::parse(&config.upstream_address) {
            Ok(addr) => addr,
            Err(e) => {
                tracing::error!(
                    "Invalid upstream address {}: {}",
                    config.upstream_address,
                    e
                );
                return Err(Box::new(e));
            }
        };

        // Handle TCP and Unix upstreams
        let bandwidth = get_global_bandwidth_tracker_or_log();
        match upstream_addr {
            UpstreamAddress::Tcp(addr) => {
                let mut stream = tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    TcpStream::connect(addr),
                )
                .await??;
                let _ = apply_tcp_socket_options(&stream, socket_options);
                match copy_bidirectional_native(&mut client_stream, &mut stream).await {
                    Ok((client_bytes, upstream_bytes)) => {
                        if let Some(bandwidth) = &bandwidth {
                            bandwidth.record_ingress(client_bytes, BandwidthProtocol::Tcp);
                            bandwidth.record_egress(
                                client_bytes,
                                BandwidthProtocol::Tcp,
                                EgressDirection::Proxied,
                            );
                            bandwidth.record_proxied(
                                client_bytes,
                                upstream_bytes,
                                &addr.to_string(),
                            );
                        }
                    }
                    Err(e) => {
                        return Err(Box::new(std::io::Error::other(e.to_string())));
                    }
                }
            }
            UpstreamAddress::Unix(path) => {
                let mut stream = tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    UnixStream::connect(&path),
                )
                .await??;
                match copy_bidirectional_native(&mut client_stream, &mut stream).await {
                    Ok((client_bytes, upstream_bytes)) => {
                        let path_str = path.to_string_lossy().to_string();
                        if let Some(bandwidth) = &bandwidth {
                            bandwidth.record_ingress(client_bytes, BandwidthProtocol::Tcp);
                            bandwidth.record_egress(
                                client_bytes,
                                BandwidthProtocol::Tcp,
                                EgressDirection::Proxied,
                            );
                            bandwidth.record_proxied(client_bytes, upstream_bytes, &path_str);
                        }
                    }
                    Err(e) => {
                        return Err(Box::new(std::io::Error::other(e.to_string())));
                    }
                }
            }
            UpstreamAddress::QuicTunnel { ref peer, port } => {
                let registry = tunnel::QUIC_TUNNEL_REGISTRY.clone();
                let runtime = registry.get_runtime().await;

                let runtime = match runtime {
                    Some(r) => r,
                    None => {
                        tracing::error!("QUIC tunnel runtime not available for {}:{}", peer, port);
                        return Err("QUIC tunnel runtime not available".into());
                    }
                };

                let identifier = format!("tcp-port-{}", port);

                let (mut send_stream, mut recv_stream) =
                    match runtime.open_tunnel_stream_to_peer(peer, &identifier).await {
                        Ok(streams) => streams,
                        Err(e) => {
                            tracing::error!(
                                "Failed to open QUIC tunnel stream for {}:{}: {}",
                                peer,
                                port,
                                e
                            );
                            return Err(e);
                        }
                    };

                let stream_open = TunnelMessage::StreamOpen {
                    identifier: identifier.clone(),
                    port,
                    protocol: "tcp".to_string(),
                    tls_passthrough: false,
                };
                let data = stream_open
                    .encode()
                    .map_err(|e| format!("Failed to encode StreamOpen: {}", e))?;
                let len = (data.len() as u32).to_be_bytes();
                send_stream
                    .write_all(&len)
                    .await
                    .map_err(|e| format!("Failed to write StreamOpen length: {}", e))?;
                send_stream
                    .write_all(&data)
                    .await
                    .map_err(|e| format!("Failed to write StreamOpen: {}", e))?;

                let mut len_buf = [0u8; 4];
                recv_stream
                    .read_exact(&mut len_buf)
                    .await
                    .map_err(|e| format!("Failed to read ack length: {}", e))?;
                let ack_len = u32::from_be_bytes(len_buf) as usize;
                let mut ack_data = vec![0u8; ack_len];
                recv_stream
                    .read_exact(&mut ack_data)
                    .await
                    .map_err(|e| format!("Failed to read ack: {}", e))?;

                let ack = TunnelMessage::decode(&ack_data)
                    .ok_or_else(|| "Failed to decode ack".to_string())?;

                match ack {
                    TunnelMessage::StreamOpenAck {
                        success, message, ..
                    } => {
                        if !success {
                            let msg = message.unwrap_or_else(|| "Unknown error".to_string());
                            tracing::error!(
                                "QUIC tunnel stream open failed for {}:{}: {}",
                                peer,
                                port,
                                msg
                            );
                            return Err(format!("Stream open failed: {}", msg).into());
                        }
                    }
                    _ => {
                        tracing::error!("Unexpected response to StreamOpen for {}:{}", peer, port);
                        return Err("Unexpected response to StreamOpen".into());
                    }
                }

                counter!("maluwaf.tcp.quic_tunnel.streams.opened").increment(1);

                let (mut client_read, mut client_write) = client_stream.split();
                let identifier_ref = identifier.clone();
                let client_to_quic = async {
                    let mut pooled = BufferPool::acquire(buffer_size);
                    let mut sequence: u64 = 0;
                    loop {
                        match client_read.read(pooled.as_mut_slice()).await {
                            Ok(0) => {
                                TunnelMessage::write_data_chunk_zero_copy(
                                    &mut send_stream,
                                    &identifier_ref,
                                    sequence,
                                    &[],
                                    true,
                                )
                                .await
                                .map_err(|e| format!("Zero-copy write error: {}", e))?;
                                break Ok::<_, Box<dyn std::error::Error + Send + Sync>>(());
                            }
                            Ok(n) => {
                                TunnelMessage::write_data_chunk_zero_copy(
                                    &mut send_stream,
                                    &identifier_ref,
                                    sequence,
                                    &pooled.as_slice()[..n],
                                    false,
                                )
                                .await
                                .map_err(|e| format!("Zero-copy write error: {}", e))?;
                                sequence += 1;
                            }
                            Err(e) => {
                                tracing::debug!("Client read error for {}: {}", identifier_ref, e);
                                break Err(e.into());
                            }
                        }
                    }
                };

                let _identifier_ref2 = identifier.clone();
                let quic_to_client = async {
                    let mut len_buf = [0u8; 4];
                    let mut data_pooled = BufferPool::acquire_medium();
                    loop {
                        match recv_stream.read_exact(&mut len_buf).await {
                            Ok(_) => {}
                            Err(quinn::ReadExactError::FinishedEarly(_)) => break Ok(()),
                            Err(e) => break Err(e.into()),
                        }

                        let len = u32::from_be_bytes(len_buf) as usize;
                        if len > data_pooled.capacity() {
                            data_pooled = BufferPool::acquire(len);
                        } else {
                            data_pooled.resize(len);
                        }
                        recv_stream.read_exact(data_pooled.as_mut_slice()).await?;

                        if let Some((_, _, data, fin)) =
                            TunnelMessage::decode_data_chunk_zero_copy(data_pooled.as_slice())
                        {
                            if !data.is_empty() {
                                client_write.write_all(data).await?;
                            }
                            if fin {
                                break Ok(());
                            }
                        } else if let Some(msg) = TunnelMessage::decode(data_pooled.as_slice()) {
                            match msg {
                                TunnelMessage::DataChunk { data, fin, .. } => {
                                    if !data.is_empty() {
                                        client_write.write_all(&data).await?;
                                    }
                                    if fin {
                                        break Ok(());
                                    }
                                }
                                TunnelMessage::StreamClose { .. } => break Ok(()),
                                _ => {}
                            }
                        }
                    }
                };

                let result = tokio::try_join!(client_to_quic, quic_to_client);

                let _ = send_stream.finish();

                counter!("maluwaf.tcp.quic_tunnel.streams.closed").increment(1);

                result?;
            }
        }

        counter!("maluwaf.tcp.connections_proxied").increment(1);
        histogram!("maluwaf.tcp.connection_duration").record(start.elapsed());

        Ok(())
    }

    async fn stall_connection(mut stream: TcpStream, socket_options: &TcpSocketOptions) {
        if socket_options.nodelay {
            let _ = stream.set_nodelay(true);
        }
        let mut pooled = BufferPool::acquire_small();

        loop {
            match tokio::time::timeout(
                std::time::Duration::from_secs(300),
                stream.read(pooled.as_mut_slice()),
            )
            .await
            {
                Ok(Ok(0)) => break,
                Ok(Ok(_)) => continue,
                Ok(Err(_)) => break,
                Err(_) => break,
            }
        }
    }

    pub async fn shutdown(&self) {
        let _ = self.shutdown_tx.send(());
        tracing::info!("TCP listener pool shutdown initiated");
    }

    pub fn listener_count(&self) -> usize {
        self.listeners.read().len()
    }
}
