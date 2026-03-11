use std::sync::Arc;
use std::net::SocketAddr;
use std::path::PathBuf;
use tokio::net::{TcpListener, TcpStream, UnixStream};
use tokio::sync::broadcast;
use tokio::io::{AsyncReadExt, AsyncWriteExt, AsyncRead, AsyncWrite};
use parking_lot::RwLock as PLRwLock;
use metrics::{counter, histogram, gauge};
use quinn::{SendStream, RecvStream};

use crate::tcp::protocol::ProtocolDetector;
use crate::tcp::filter::{ProtocolFilter, FilterAction};
use crate::waf::{RateLimiterManager, RateLimitResult, FloodProtector, FloodDecision};
use crate::upstream::{UpstreamAddress, SocketErrorTracker};
use crate::tunnel;
use crate::tunnel::quic::messages::TunnelMessage;

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
}

#[derive(Debug, Clone)]
pub struct TcpListenerPoolConfig {
    pub worker_pool_size: usize,
    pub connection_timeout_secs: u64,
    pub max_connections: usize,
}

impl Default for TcpListenerPoolConfig {
    fn default() -> Self {
        Self {
            worker_pool_size: 4,
            connection_timeout_secs: 5,
            max_connections: 1000,
        }
    }
}

#[derive(Debug, Clone)]
struct TcpListenerInstance {
    config: TcpListenerConfig,
    listen_addr: SocketAddr,
}

impl TcpListenerPool {
    pub fn new(
        pool_config: TcpListenerPoolConfig,
        filter_config: crate::tcp::filter::FilterConfig,
    ) -> Self {
        let (shutdown_tx, _) = broadcast::channel(1);

        Self {
            config: pool_config,
            listeners: Arc::new(PLRwLock::new(Vec::new())),
            shutdown_tx,
            protocol_detector: ProtocolDetector::new(),
            protocol_filter: ProtocolFilter::new(filter_config),
            rate_limiter: None,
            flood_protector: None,
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

    pub async fn add_listener(&self, listener_config: TcpListenerConfig) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let bind_addr = format!("{}:{}", listener_config.bind_address, listener_config.port);
        let listener = TcpListener::bind(&bind_addr).await?;
        let local_addr = listener.local_addr()?;

        tracing::info!("TCP listener bound to {} for protocol {}", local_addr, listener_config.expected_protocol);

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
        
        for instance in listeners {
            let config = instance.config.clone();
            let shutdown_rx = self.shutdown_tx.subscribe();
            let detector = self.protocol_detector.clone();
            let filter = self.protocol_filter.clone();
            let rate_limiter = self.rate_limiter.clone();
            let flood_protector = self.flood_protector.clone();

            tokio::spawn(async move {
                Self::listen_loop(config, shutdown_rx, detector, filter, rate_limiter, flood_protector).await;
            });
        }

        tracing::info!("TCP listener pool started with {} listeners", listener_count);
    }

    async fn listen_loop(
        config: TcpListenerConfig,
        mut shutdown_rx: broadcast::Receiver<()>,
        detector: ProtocolDetector,
        filter: ProtocolFilter,
        rate_limiter: Option<Arc<RateLimiterManager>>,
        flood_protector: Option<Arc<FloodProtector>>,
    ) {
        let bind_addr = format!("{}:{}", config.bind_address, config.port);
        let listener = match TcpListener::bind(&bind_addr).await {
            Ok(l) => l,
            Err(e) => {
                tracing::error!("Failed to bind TCP listener on {}: {}", bind_addr, e);
                return;
            }
        };

        tracing::info!("TCP listener running on {} for protocol {}", bind_addr, config.expected_protocol);

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
                                        counter!("rustwaf.tcp.flood_blackhole").increment(1);
                                        continue;
                                    }
                                    FloodDecision::RateLimited => {
                                        counter!("rustwaf.tcp.flood_limited").increment(1);
                                        continue;
                                    }
                                    FloodDecision::Allowed => {}
                                }
                                fp.register_half_open(client_ip);
                            }
                            
                            if let Some(ref rl) = rate_limiter {
                                if rl.is_in_blackhole() {
                                    counter!("rustwaf.tcp.blackhole_drop").increment(1);
                                    continue;
                                }
                                
                                match rl.check_global() {
                                    RateLimitResult::Blackholed => {
                                        counter!("rustwaf.tcp.blackhole_drop").increment(1);
                                        continue;
                                    }
                                    RateLimitResult::Limited { limit_type, .. } => {
                                        tracing::debug!("TCP global rate limited: {}", limit_type);
                                        counter!("rustwaf.tcp.rate_limited").increment(1);
                                        continue;
                                    }
                                    RateLimitResult::Allowed => {}
                                }
                            }

                            let config = config.clone();
                            let detector = detector.clone();
                            let filter = filter.clone();
                            let rate_limiter = rate_limiter.clone();
                            let flood_protector = flood_protector.clone();

                            tokio::spawn(async move {
                                if let Err(e) = Self::handle_connection(stream, client_addr, &config, &detector, &filter, rate_limiter.as_ref(), flood_protector.as_ref()).await {
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
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let start = std::time::Instant::now();
        let client_ip = client_addr.ip();

        if let Some(rl) = rate_limiter {
            match rl.check_rate_limit(client_ip).await {
                RateLimitResult::Limited { limit_type, .. } => {
                    tracing::debug!("TCP rate limited: {} for {}", limit_type, client_ip);
                    counter!("rustwaf.tcp.ip_rate_limited").increment(1);
                    return Ok(());
                }
                RateLimitResult::Blackholed => {
                    counter!("rustwaf.tcp.blackhole_drop").increment(1);
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
                    counter!("rustwaf.tcp.protocol_rejected").increment(1);
                    Self::stall_connection(client_stream).await;
                    histogram!("rustwaf.tcp.connection_duration").record(start.elapsed());
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
                    counter!("rustwaf.tcp.protocol_stalled").increment(1);
                    Self::stall_connection(client_stream).await;
                    histogram!("rustwaf.tcp.connection_duration").record(start.elapsed());
                    return Ok(());
                }
                FilterAction::Allow => {
                    counter!("rustwaf.tcp.protocol_allowed").increment(1);
                }
            }
        }
        
        if let Some(fp) = flood_protector {
            fp.register_half_open(client_ip);
        }

        let upstream_addr = match UpstreamAddress::parse(&config.upstream_address) {
            Ok(addr) => addr,
            Err(e) => {
                tracing::error!("Invalid upstream address {}: {}", config.upstream_address, e);
                return Err(Box::new(e));
            }
        };

        // Handle TCP and Unix upstreams
        match upstream_addr {
            UpstreamAddress::Tcp(addr) => {
                let stream = tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    TcpStream::connect(addr)
                ).await??;
                let mut stream = stream;
                let (mut client_read, mut client_write) = client_stream.split();
                let (mut upstream_read, mut upstream_write) = stream.split();
                let client_to_upstream = tokio::io::copy(&mut client_read, &mut upstream_write);
                let upstream_to_client = tokio::io::copy(&mut upstream_read, &mut client_write);
                tokio::try_join!(client_to_upstream, upstream_to_client)?;
            }
            UpstreamAddress::Unix(path) => {
                let stream = tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    UnixStream::connect(&path)
                ).await??;
                let mut stream = stream;
                let (mut client_read, mut client_write) = client_stream.split();
                let (mut upstream_read, mut upstream_write) = stream.split();
                let client_to_upstream = tokio::io::copy(&mut client_read, &mut upstream_write);
                let upstream_to_client = tokio::io::copy(&mut upstream_read, &mut client_write);
                tokio::try_join!(client_to_upstream, upstream_to_client)?;
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
                
                let (mut send_stream, mut recv_stream) = match runtime.open_tunnel_stream_to_peer(peer, &identifier).await {
                    Ok(streams) => streams,
                    Err(e) => {
                        tracing::error!("Failed to open QUIC tunnel stream for {}:{}: {}", peer, port, e);
                        return Err(e);
                    }
                };

                let stream_open = TunnelMessage::StreamOpen {
                    identifier: identifier.clone(),
                    port,
                    protocol: "tcp".to_string(),
                };
                let data = stream_open.encode()
                    .map_err(|e| format!("Failed to encode StreamOpen: {}", e))?;
                let len = (data.len() as u32).to_be_bytes();
                send_stream.write_all(&len).await
                    .map_err(|e| format!("Failed to write StreamOpen length: {}", e))?;
                send_stream.write_all(&data).await
                    .map_err(|e| format!("Failed to write StreamOpen: {}", e))?;

                let mut len_buf = [0u8; 4];
                recv_stream.read_exact(&mut len_buf).await
                    .map_err(|e| format!("Failed to read ack length: {}", e))?;
                let ack_len = u32::from_be_bytes(len_buf) as usize;
                let mut ack_data = vec![0u8; ack_len];
                recv_stream.read_exact(&mut ack_data).await
                    .map_err(|e| format!("Failed to read ack: {}", e))?;
                
                let ack = TunnelMessage::decode(&ack_data)
                    .ok_or_else(|| "Failed to decode ack".to_string())?;
                
                match ack {
                    TunnelMessage::StreamOpenAck { success, message, .. } => {
                        if !success {
                            let msg = message.unwrap_or_else(|| "Unknown error".to_string());
                            tracing::error!("QUIC tunnel stream open failed for {}:{}: {}", peer, port, msg);
                            return Err(format!("Stream open failed: {}", msg).into());
                        }
                    }
                    _ => {
                        tracing::error!("Unexpected response to StreamOpen for {}:{}", peer, port);
                        return Err("Unexpected response to StreamOpen".into());
                    }
                }

                counter!("rustwaf.tcp.quic_tunnel.streams.opened").increment(1);
                
                let (mut client_read, mut client_write) = client_stream.split();
                let client_to_quic = async {
                    let mut buf = vec![0u8; 64 * 1024];
                    let mut sequence: u64 = 0;
                    loop {
                        match client_read.read(&mut buf).await {
                            Ok(0) => {
                                let fin_msg = TunnelMessage::DataChunk {
                                    identifier: identifier.clone(),
                                    sequence,
                                    data: Vec::new(),
                                    fin: true,
                                };
                                let data = fin_msg.encode()
                                    .map_err(|e| format!("Encode error: {}", e))?;
                                let len = (data.len() as u32).to_be_bytes();
                                send_stream.write_all(&len).await?;
                                send_stream.write_all(&data).await?;
                                break Ok::<_, Box<dyn std::error::Error + Send + Sync>>(());
                            }
                            Ok(n) => {
                                let data_msg = TunnelMessage::DataChunk {
                                    identifier: identifier.clone(),
                                    sequence,
                                    data: buf[..n].to_vec(),
                                    fin: false,
                                };
                                let data = data_msg.encode()
                                    .map_err(|e| format!("Encode error: {}", e))?;
                                let len = (data.len() as u32).to_be_bytes();
                                send_stream.write_all(&len).await?;
                                send_stream.write_all(&data).await?;
                                sequence += 1;
                            }
                            Err(e) => {
                                tracing::debug!("Client read error for {}: {}", identifier, e);
                                break Err(e.into());
                            }
                        }
                    }
                };

                let quic_to_client = async {
                    loop {
                        let mut len_buf = [0u8; 4];
                        match recv_stream.read_exact(&mut len_buf).await {
                            Ok(_) => {}
                            Err(quinn::ReadExactError::FinishedEarly(_)) => break Ok(()),
                            Err(e) => break Err(e.into()),
                        }
                        
                        let len = u32::from_be_bytes(len_buf) as usize;
                        let mut data = vec![0u8; len];
                        recv_stream.read_exact(&mut data).await?;
                        
                        let msg = TunnelMessage::decode(&data)
                            .ok_or_else(|| "Failed to decode message".to_string())?;
                        
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
                };

                let result = tokio::try_join!(client_to_quic, quic_to_client);
                
                let _ = send_stream.finish();
                
                counter!("rustwaf.tcp.quic_tunnel.streams.closed").increment(1);
                
                result?;
            }
        }

        counter!("rustwaf.tcp.connections_proxied").increment(1);
        histogram!("rustwaf.tcp.connection_duration").record(start.elapsed());

        Ok(())
    }

    async fn stall_connection(mut stream: TcpStream) {
        let _ = stream.set_nodelay(true);
        let mut buf = [0u8; 1024];
        
        loop {
            match tokio::time::timeout(
                std::time::Duration::from_secs(300),
                stream.read(&mut buf)
            ).await {
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
