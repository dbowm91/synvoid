use metrics::{counter, gauge, histogram};
use parking_lot::RwLock as PLRwLock;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UnixStream};
use tokio::sync::{broadcast, Semaphore};

#[cfg(unix)]
use socket2::{Domain, Protocol, Socket, Type};

use crate::buffer::BufferPool;
use crate::metrics::bandwidth::{
    get_global_bandwidth_tracker_or_log, BandwidthProtocol, EgressDirection,
};
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
    pub reuse_port_ebpf: bool,
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
            reuse_port_ebpf: false,
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
                use std::os::fd::AsRawFd;
                let fd = stream.as_raw_fd();
                // SAFETY: fd must be a valid TCP socket. The result is explicitly ignored
                // (let _) because setsockopt failure is non-fatal for TCP_QUICKACK.
                let _ = unsafe {
                    libc::setsockopt(
                        fd,
                        libc::SOL_TCP,
                        libc::TCP_QUICKACK,
                        &1i32 as *const i32 as *const libc::c_void,
                        std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                    )
                };
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
        {
            socket.set_reuse_port(true)?;
            if options.reuse_port_ebpf {
                let _ = attach_reuseport_ebpf(&socket);
            }
        }
        #[cfg(not(target_os = "linux"))]
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

#[cfg(target_os = "linux")]
fn attach_reuseport_ebpf(
    socket: &socket2::Socket,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    use std::os::fd::AsRawFd;

    // In a real implementation, we would load the BPF bytecode from a file or embedded bytes.
    // For this architectural improvement, we provide the loader infrastructure.
    tracing::debug!(
        "Attaching eBPF reuseport balancer to socket {}",
        socket.as_raw_fd()
    );

    // Placeholder for actual BPF loading logic:
    // let mut bpf = aya::Bpf::load(BPF_BYTES)?;
    // let program: &mut aya::programs::SkReuseport = bpf.program_mut("balance_workers")?.try_into()?;
    // program.load()?;
    // program.attach(socket.as_raw_fd())?;

    Ok(())
}

fn format_bind_address(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
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
    pub tcp_backlog: Option<u32>,
    /// Idle timeout for proxied traffic. Not a whole-connection lifetime cap.
    pub idle_timeout_secs: u64,
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
            tcp_backlog: None,
            idle_timeout_secs: 300,
        }
    }
}

#[derive(Clone)]
pub struct TcpListenerPool {
    config: TcpListenerPoolConfig,
    registered: Arc<PLRwLock<Vec<RegisteredTcpListener>>>,
    bound: Arc<PLRwLock<Vec<BoundTcpListener>>>,
    shutdown_tx: broadcast::Sender<()>,
    protocol_detector: ProtocolDetector,
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
            worker_pool_size: std::thread::available_parallelism()
                .map(|p| p.get())
                .unwrap_or(4),
            connection_timeout_secs: 5,
            max_connections: 10000,
            socket_options: TcpSocketOptions::default(),
            buffer_size: 64 * 1024,
            enable_concurrency_limit: true,
        }
    }
}

#[derive(Debug, thiserror::Error)]
#[error("failed to bind TCP listener {address}: {source}")]
pub struct TcpListenerBindError {
    pub address: String,
    #[source]
    pub source: std::io::Error,
}

#[derive(Debug, Clone)]
struct RegisteredTcpListener {
    config: TcpListenerConfig,
    active_connections: Arc<AtomicUsize>,
}

#[derive(Debug, Clone)]
struct BoundTcpListener {
    registered: RegisteredTcpListener,
    listener: Arc<TcpListener>,
    local_addr: SocketAddr,
}

/// Process-local view of the bound TCP listeners, used by the admin API.
///
/// The admin control plane runs in the same process as the data plane, so a
/// read-only snapshot is the truthful source for "what is actually listening"
/// and "how many connections are active right now". It is not a control
/// channel and it does not pretend to aggregate remote workers.
#[derive(Debug, Clone)]
pub struct TcpListenerSnapshot {
    pub protocol: String,
    pub bind_address: String,
    pub port: u16,
    pub upstream: String,
    pub bound: bool,
    pub active_connections: usize,
    pub workers: usize,
}

struct TcpRegistryEntry {
    snapshot: TcpListenerSnapshot,
    active_connections: Arc<AtomicUsize>,
}

static TCP_LISTENER_REGISTRY: LazyLock<PLRwLock<Vec<TcpRegistryEntry>>> =
    LazyLock::new(|| PLRwLock::new(Vec::new()));

pub fn tcp_listener_snapshots() -> Vec<TcpListenerSnapshot> {
    TCP_LISTENER_REGISTRY
        .read()
        .iter()
        .map(|entry| {
            let mut snapshot = entry.snapshot.clone();
            snapshot.active_connections = entry.active_connections.load(Ordering::Relaxed);
            snapshot
        })
        .collect()
}

struct ActiveConnectionGuard(Arc<AtomicUsize>);

impl Drop for ActiveConnectionGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

impl TcpListenerPool {
    pub fn new(pool_config: TcpListenerPoolConfig) -> Self {
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
            registered: Arc::new(PLRwLock::new(Vec::new())),
            bound: Arc::new(PLRwLock::new(Vec::new())),
            shutdown_tx,
            protocol_detector: ProtocolDetector::new(),
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

    /// Register a listener definition. No socket is opened here.
    ///
    /// `bind_all` performs the single bind, so a registration failure cannot
    /// leave a half-open socket behind and `start` cannot bind a second one.
    pub fn add_listener(&self, listener_config: TcpListenerConfig) {
        if listener_config.port < 1024 {
            #[cfg(unix)]
            {
                if unsafe { libc::getuid() != 0 && libc::geteuid() != 0 } {
                    tracing::warn!(
                        "Binding to privileged port {} requires root or CAP_NET_BIND_SERVICE.",
                        listener_config.port
                    );
                }
            }
            #[cfg(windows)]
            {
                tracing::warn!(
                    "Binding to privileged port {} may require Administrator privileges on Windows.",
                    listener_config.port
                );
            }
        }

        self.registered.write().push(RegisteredTcpListener {
            config: listener_config,
            active_connections: Arc::new(AtomicUsize::new(0)),
        });
    }

    /// Bind every registered listener exactly once.
    ///
    /// Startup calls this before spawning tasks and treats an error as fatal.
    /// Calling it again after a successful bind is a no-op.
    pub async fn bind_all(&self) -> Result<(), TcpListenerBindError> {
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
            let listener = {
                let addr: SocketAddr =
                    bind_addr
                        .parse::<SocketAddr>()
                        .map_err(|e| TcpListenerBindError {
                            address: bind_addr.clone(),
                            source: std::io::Error::new(
                                std::io::ErrorKind::InvalidInput,
                                e.to_string(),
                            ),
                        })?;

                let socket =
                    create_socket_with_options(addr, &self.socket_options).map_err(|e| {
                        TcpListenerBindError {
                            address: bind_addr.clone(),
                            source: e,
                        }
                    })?;
                socket
                    .bind(&addr.into())
                    .map_err(|e| TcpListenerBindError {
                        address: bind_addr.clone(),
                        source: e,
                    })?;
                let backlog = entry.config.tcp_backlog.unwrap_or(4096);
                socket
                    .listen(backlog as i32)
                    .map_err(|e| TcpListenerBindError {
                        address: bind_addr.clone(),
                        source: e,
                    })?;
                let std_listener: std::net::TcpListener = socket.into();
                TcpListener::from_std(std_listener).map_err(|e| TcpListenerBindError {
                    address: bind_addr.clone(),
                    source: e,
                })?
            };

            #[cfg(not(unix))]
            let listener =
                TcpListener::bind(&bind_addr)
                    .await
                    .map_err(|e| TcpListenerBindError {
                        address: bind_addr.clone(),
                        source: e,
                    })?;

            let local_addr = listener.local_addr().map_err(|e| TcpListenerBindError {
                address: bind_addr.clone(),
                source: e,
            })?;

            tracing::info!(
                address = %local_addr,
                protocol = %entry.config.expected_protocol,
                upstream = %entry.config.upstream_address,
                workers,
                "TCP listener bound"
            );

            registry_entries.push(TcpRegistryEntry {
                snapshot: TcpListenerSnapshot {
                    protocol: entry.config.expected_protocol.clone(),
                    bind_address: entry.config.bind_address.clone(),
                    port: local_addr.port(),
                    upstream: entry.config.upstream_address.clone(),
                    bound: true,
                    active_connections: 0,
                    workers,
                },
                active_connections: entry.active_connections.clone(),
            });

            bound.push(BoundTcpListener {
                registered: entry,
                listener: Arc::new(listener),
                local_addr,
            });
        }

        *self.bound.write() = bound;
        {
            // The registry is process-wide and may already hold listeners from
            // another pool (tests, or a future multi-pool composition). Merge
            // this pool's entries instead of replacing the whole inventory.
            let mut registry = TCP_LISTENER_REGISTRY.write();
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
                tracing::error!("TCP listener pool failed to bind: {}", e);
                return;
            }
        }

        let bound = self.bound.read().clone();
        let listener_count = bound.len();
        let workers_per_listener = self.config.worker_pool_size.max(1);
        let socket_options = self.socket_options.clone();
        let connection_semaphore = self.connection_semaphore.clone();
        let buffer_size = self.buffer_size;
        let connection_timeout_secs = self.config.connection_timeout_secs;

        gauge!("synvoid.tcp.pool.max_connections").set(self.config.max_connections as f64);

        for instance in bound {
            let filter = ProtocolFilter::new(crate::tcp::filter::FilterConfig {
                enabled: instance.registered.config.filter_enabled,
                strict_mode: instance.registered.config.strict_mode,
                ..Default::default()
            });

            for worker_id in 0..workers_per_listener {
                let config = instance.registered.config.clone();
                let active = instance.registered.active_connections.clone();
                let listener = instance.listener.clone();
                let shutdown_rx = self.shutdown_tx.subscribe();
                let detector = self.protocol_detector.clone();
                let filter = filter.clone();
                let rate_limiter = self.rate_limiter.clone();
                let flood_protector = self.flood_protector.clone();
                let sock_opts = socket_options.clone();
                let semaphore = connection_semaphore.clone();

                tokio::spawn(async move {
                    Self::listen_loop(
                        listener,
                        config,
                        active,
                        worker_id,
                        shutdown_rx,
                        detector,
                        filter,
                        rate_limiter,
                        flood_protector,
                        sock_opts,
                        semaphore,
                        buffer_size,
                        connection_timeout_secs,
                    )
                    .await;
                });
            }
        }

        tracing::info!(
            "TCP listener pool started with {} listeners x {} accept loops (max_conns: {}, buffer: {}KB)",
            listener_count,
            workers_per_listener,
            self.config.max_connections,
            buffer_size / 1024
        );
    }

    async fn copy_direction<R, W>(
        reader: &mut R,
        writer: &mut W,
        idle: Duration,
    ) -> std::io::Result<u64>
    where
        R: AsyncRead + Unpin,
        W: AsyncWrite + Unpin,
    {
        let mut buffer = BufferPool::acquire_medium();
        let mut total = 0u64;
        loop {
            let n = match tokio::time::timeout(idle, reader.read(buffer.as_mut_slice())).await {
                Err(_) => {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "proxied connection idle timeout",
                    ));
                }
                Ok(Ok(0)) => {
                    let _ = writer.shutdown().await;
                    return Ok(total);
                }
                Ok(Ok(n)) => n,
                Ok(Err(e)) => return Err(e),
            };
            tokio::time::timeout(idle, writer.write_all(&buffer.as_slice()[..n]))
                .await
                .map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "proxied connection write idle timeout",
                    )
                })??;
            writer.flush().await?;
            total = total.saturating_add(n as u64);
        }
    }

    async fn listen_loop(
        listener: Arc<TcpListener>,
        config: TcpListenerConfig,
        active_connections: Arc<AtomicUsize>,
        worker_id: usize,
        mut shutdown_rx: broadcast::Receiver<()>,
        detector: ProtocolDetector,
        filter: ProtocolFilter,
        rate_limiter: Option<Arc<RateLimiterManager>>,
        flood_protector: Option<Arc<FloodProtector>>,
        socket_options: TcpSocketOptions,
        connection_semaphore: Option<Arc<Semaphore>>,
        buffer_size: usize,
        connection_timeout_secs: u64,
    ) {
        let bind_addr = format_bind_address(&config.bind_address, config.port);

        tracing::info!(
            address = %bind_addr,
            protocol = %config.expected_protocol,
            worker = worker_id,
            "TCP listener accept loop running"
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
                                        counter!("synvoid.tcp.flood_blackhole").increment(1);
                                        continue;
                                    }
                                    FloodDecision::RateLimited => {
                                        counter!("synvoid.tcp.flood_limited").increment(1);
                                        continue;
                                    }
                                    FloodDecision::Allowed => {}
                                }
                                fp.register_half_open(client_ip);
                            }

                            if let Some(ref rl) = rate_limiter {
                                if rl.is_in_blackhole() {
                                    counter!("synvoid.tcp.blackhole_drop").increment(1);
                                    continue;
                                }

                                match rl.check_global() {
                                    RateLimitResult::Blackholed => {
                                        counter!("synvoid.tcp.blackhole_drop").increment(1);
                                        continue;
                                    }
                                    RateLimitResult::Limited { limit_type, .. } => {
                                        tracing::debug!("TCP global rate limited: {}", limit_type);
                                        counter!("synvoid.tcp.rate_limited").increment(1);
                                        continue;
                                    }
                                    RateLimitResult::Allowed => {}
                                }
                            }

                            let permit = if let Some(ref sem) = connection_semaphore {
                                match sem.clone().try_acquire_owned() {
                                    Ok(p) => Some(p),
                                    Err(_) => {
                                        counter!("synvoid.tcp.connection_limit_exceeded").increment(1);
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
                            let active = active_connections.clone();

                            let _ = apply_tcp_socket_options(&stream, &sock_opts);

                            active.fetch_add(1, Ordering::Relaxed);
                            tokio::spawn(async move {
                                let _active = ActiveConnectionGuard(active);
                                let _permit = permit;
                                if let Err(e) = Self::handle_connection(
                                    stream,
                                    client_addr,
                                    &config,
                                    &detector,
                                    &filter,
                                    rate_limiter.as_ref(),
                                    flood_protector.as_ref(),
                                    &sock_opts,
                                    buffer_size,
                                    connection_timeout_secs,
                                )
                                .await
                                {
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
        connection_timeout_secs: u64,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let start = std::time::Instant::now();
        let client_ip = client_addr.ip();

        if let Some(rl) = rate_limiter {
            match rl.check_rate_limit(Some("global"), client_ip).await {
                RateLimitResult::Limited { limit_type, .. } => {
                    tracing::debug!("TCP rate limited: {} for {}", limit_type, client_ip);
                    counter!("synvoid.tcp.ip_rate_limited").increment(1);
                    return Ok(());
                }
                RateLimitResult::Blackholed => {
                    counter!("synvoid.tcp.blackhole_drop").increment(1);
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
                    counter!("synvoid.tcp.protocol_rejected").increment(1);
                    Self::stall_connection(client_stream, socket_options).await;
                    histogram!("synvoid.tcp.connection_duration").record(start.elapsed());
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
                    counter!("synvoid.tcp.protocol_stalled").increment(1);
                    Self::stall_connection(client_stream, socket_options).await;
                    histogram!("synvoid.tcp.connection_duration").record(start.elapsed());
                    return Ok(());
                }
                FilterAction::Allow => {
                    counter!("synvoid.tcp.protocol_allowed").increment(1);
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
                    Duration::from_secs(connection_timeout_secs),
                    TcpStream::connect(addr),
                )
                .await??;
                let _ = apply_tcp_socket_options(&stream, socket_options);
                match copy_bidirectional_idle(
                    &mut client_stream,
                    &mut stream,
                    Duration::from_secs(config.idle_timeout_secs.max(1)),
                )
                .await
                {
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
                    Duration::from_secs(connection_timeout_secs),
                    UnixStream::connect(&path),
                )
                .await??;
                match copy_bidirectional_idle(
                    &mut client_stream,
                    &mut stream,
                    Duration::from_secs(config.idle_timeout_secs.max(1)),
                )
                .await
                {
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

                counter!("synvoid.tcp.quic_tunnel.streams.opened").increment(1);

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

                counter!("synvoid.tcp.quic_tunnel.streams.closed").increment(1);

                result?;
            }
        }

        counter!("synvoid.tcp.connections_proxied").increment(1);
        histogram!("synvoid.tcp.connection_duration").record(start.elapsed());

        Ok(())
    }

    pub fn bound_addresses(&self) -> Vec<SocketAddr> {
        self.bound.read().iter().map(|b| b.local_addr).collect()
    }

    pub fn worker_accept_loop_count(&self) -> usize {
        self.bound.read().len() * self.config.worker_pool_size.max(1)
    }

    pub fn active_connection_count(&self) -> usize {
        self.registered
            .read()
            .iter()
            .map(|r| r.active_connections.load(Ordering::Relaxed))
            .sum()
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
        let bound = self.bound.read().clone();
        {
            let mut registry = TCP_LISTENER_REGISTRY.write();
            registry.retain(|entry| {
                !bound.iter().any(|listener| {
                    listener.local_addr.port() == entry.snapshot.port
                        && listener.registered.config.bind_address == entry.snapshot.bind_address
                        && listener.registered.config.expected_protocol == entry.snapshot.protocol
                })
            });
        }
        tracing::info!("TCP listener pool shutdown initiated");
    }

    pub fn listener_count(&self) -> usize {
        self.registered.read().len()
    }
}

async fn copy_bidirectional_idle<A, B>(
    client: &mut A,
    upstream: &mut B,
    idle: Duration,
) -> std::io::Result<(u64, u64)>
where
    A: AsyncRead + AsyncWrite + Unpin,
    B: AsyncRead + AsyncWrite + Unpin,
{
    let (mut client_read, mut client_write) = tokio::io::split(&mut *client);
    let (mut upstream_read, mut upstream_write) = tokio::io::split(&mut *upstream);

    let client_to_upstream =
        TcpListenerPool::copy_direction(&mut client_read, &mut upstream_write, idle);
    let upstream_to_client =
        TcpListenerPool::copy_direction(&mut upstream_read, &mut client_write, idle);

    tokio::try_join!(client_to_upstream, upstream_to_client)
}
