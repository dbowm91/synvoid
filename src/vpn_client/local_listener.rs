#![allow(unused_variables, dead_code)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use metrics::{counter, gauge};
use quinn::Connection;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream, UdpSocket};
use tokio::sync::broadcast;

use crate::buffer::BufferPool;
use crate::tunnel::quic::framing::{read_message_default, write_message};
use crate::tunnel::quic::messages::{DatagramCapabilities, DatagramMessage, TunnelMessage};

const MAX_UDP_CLIENTS: usize = 10000;
const UDP_CLIENT_TTL_SECS: u64 = 300;
const UDP_CLEANUP_INTERVAL_SECS: u64 = 60;

#[derive(Clone)]
pub struct LocalPortMapping {
    pub local_addr: SocketAddr,
    pub remote_port: u16,
    pub protocol: Protocol,
    pub upstream_host: String,
    pub identifier: String,
}

#[derive(Clone, Copy, Debug)]
pub enum Protocol {
    Tcp,
    Udp,
}

impl std::fmt::Display for Protocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Protocol::Tcp => write!(f, "tcp"),
            Protocol::Udp => write!(f, "udp"),
        }
    }
}

pub struct LocalListener {
    mapping: LocalPortMapping,
    connection: Connection,
    datagram_caps: DatagramCapabilities,
    shutdown_tx: broadcast::Sender<()>,
}

struct UdpClientTracker {
    timestamps: Arc<DashMap<SocketAddr, Instant>>,
    last_sequence: Arc<std::sync::atomic::AtomicU64>,
    cleanup_cursor: Arc<std::sync::atomic::AtomicU64>,
    max_cleanup_per_batch: usize,
}

impl UdpClientTracker {
    fn new() -> Self {
        Self {
            timestamps: Arc::new(DashMap::new()),
            last_sequence: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            cleanup_cursor: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            max_cleanup_per_batch: 100,
        }
    }

    fn register(&self, addr: SocketAddr) -> bool {
        if self.timestamps.len() >= MAX_UDP_CLIENTS {
            counter!("maluwaf.vpn.client.udp.client_map_full").increment(1);
            return false;
        }

        self.timestamps.insert(addr, Instant::now());
        true
    }

    fn lookup_by_source(&self, source_addr: &str) -> Option<SocketAddr> {
        source_addr
            .parse::<SocketAddr>()
            .ok()
            .filter(|addr| self.timestamps.contains_key(addr))
    }

    fn cleanup_expired(&self) {
        let now = Instant::now();
        let ttl = Duration::from_secs(UDP_CLIENT_TTL_SECS);

        let mut cleaned = 0;
        let max_clean = self.max_cleanup_per_batch;

        let keys_to_remove: Vec<SocketAddr> = self
            .timestamps
            .iter()
            .filter(|e| {
                if cleaned >= max_clean {
                    return false;
                }
                if now.duration_since(*e.value()) > ttl {
                    cleaned += 1;
                    return true;
                }
                false
            })
            .map(|e| *e.key())
            .collect();

        for addr in keys_to_remove {
            self.timestamps.remove(&addr);
        }

        let remaining = self.timestamps.len();
        gauge!("maluwaf.vpn.client.udp.active_clients").set(remaining as f64);
    }

    fn client_count(&self) -> usize {
        self.timestamps.len()
    }
}

impl LocalListener {
    pub fn new(
        mapping: LocalPortMapping,
        connection: Connection,
        datagram_caps: DatagramCapabilities,
    ) -> Self {
        let (shutdown_tx, _) = broadcast::channel(1);

        Self {
            mapping,
            connection,
            datagram_caps,
            shutdown_tx,
        }
    }

    pub fn identifier(&self) -> &str {
        &self.mapping.identifier
    }

    pub async fn start(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        match self.mapping.protocol {
            Protocol::Tcp => self.start_tcp().await,
            Protocol::Udp => self.start_udp().await,
        }
    }

    async fn find_available_port(&self) -> u16 {
        use tokio::net::TcpListener;

        let base_port = self.mapping.local_addr.port();
        let host = self.mapping.local_addr.ip();

        for port in base_port..=base_port.saturating_add(100) {
            if TcpListener::bind((host, port)).await.is_ok() {
                return port;
            }
        }

        base_port
    }

    async fn start_tcp(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let listener = match TcpListener::bind(self.mapping.local_addr).await {
            Ok(l) => l,
            Err(e) if e.kind() == std::io::ErrorKind::AddrInUse => {
                let suggested_port = self.find_available_port().await;
                return Err(format!(
                    "Port {} is already in use. Try using port {} instead.",
                    self.mapping.local_addr.port(),
                    suggested_port
                )
                .into());
            }
            Err(e) => return Err(e.into()),
        };
        let local_addr = listener.local_addr()?;

        tracing::info!(
            "TCP listener started on {} -> remote:{}",
            local_addr,
            self.mapping.remote_port
        );

        let shutdown_rx = self.shutdown_tx.subscribe();
        let connection = self.connection.clone();
        let mapping = self.mapping.clone();

        tokio::spawn(async move {
            Self::tcp_accept_loop(listener, connection, mapping, shutdown_rx).await;
        });

        Ok(())
    }

    async fn tcp_accept_loop(
        listener: TcpListener,
        connection: Connection,
        mapping: LocalPortMapping,
        mut shutdown_rx: broadcast::Receiver<()>,
    ) {
        loop {
            tokio::select! {
                accept_result = listener.accept() => {
                    match accept_result {
                        Ok((tcp_stream, client_addr)) => {
                            let conn = connection.clone();
                            let map = mapping.clone();

                            counter!("maluwaf.vpn.client.tcp.connections").increment(1);

                            tokio::spawn(async move {
                                if let Err(e) = Self::handle_tcp_connection(tcp_stream, conn, map).await {
                                    tracing::debug!("TCP connection error from {}: {}", client_addr, e);
                                }
                            });
                        }
                        Err(e) => {
                            tracing::warn!("TCP accept error: {}", e);
                        }
                    }
                }
                _ = shutdown_rx.recv() => {
                    tracing::info!("TCP listener shutting down");
                    break;
                }
            }
        }
    }

    async fn handle_tcp_connection(
        mut tcp_stream: TcpStream,
        connection: Connection,
        mapping: LocalPortMapping,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let (mut send_stream, mut recv_stream) = connection
            .open_bi()
            .await
            .map_err(|e| format!("Failed to open stream: {}", e))?;

        let stream_open = TunnelMessage::StreamOpen {
            identifier: mapping.identifier.clone(),
            port: mapping.remote_port,
            protocol: "tcp".to_string(),
            tls_passthrough: false,
        };
        write_message(&mut send_stream, &stream_open).await?;

        let response = read_message_default(&mut recv_stream).await?;

        match response {
            TunnelMessage::StreamOpenAck {
                success, message, ..
            } => {
                if !success {
                    return Err(
                        format!("Stream open failed: {}", message.unwrap_or_default()).into(),
                    );
                }
            }
            _ => return Err("Unexpected response to StreamOpen".into()),
        }

        let (mut tcp_read, mut tcp_write) = tcp_stream.split();

        let identifier = mapping.identifier.clone();
        let tcp_to_quic = async {
            let mut pooled = BufferPool::acquire(64 * 1024);
            let mut sequence: u64 = 0;
            loop {
                match tcp_read.read(pooled.as_mut_slice()).await {
                    Ok(0) => {
                        let fin_msg = TunnelMessage::DataChunk {
                            identifier: identifier.clone(),
                            sequence,
                            data: Vec::new(),
                            fin: true,
                        };
                        let data = fin_msg
                            .encode()
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
                            data: pooled.as_slice()[..n].to_vec(),
                            fin: false,
                        };
                        let data = data_msg
                            .encode()
                            .map_err(|e| format!("Encode error: {}", e))?;
                        let len = (data.len() as u32).to_be_bytes();
                        send_stream.write_all(&len).await?;
                        send_stream.write_all(&data).await?;
                        sequence += 1;
                    }
                    Err(e) => {
                        tracing::debug!("TCP read error: {}", e);
                        break Err(e.into());
                    }
                }
            }
        };

        let identifier = mapping.identifier.clone();
        let max_msg_size = 64 * 1024;
        let quic_to_tcp = async {
            let mut len_buf = [0u8; 4];
            let mut data_pooled = BufferPool::acquire_medium();
            loop {
                match recv_stream.read_exact(&mut len_buf).await {
                    Ok(_) => {}
                    Err(quinn::ReadExactError::FinishedEarly(_)) => break Ok(()),
                    Err(e) => break Err(e.into()),
                }

                let len = u32::from_be_bytes(len_buf) as usize;
                if len > max_msg_size {
                    break Err(format!("Message too large: {} > {}", len, max_msg_size).into());
                }
                if len > data_pooled.capacity() {
                    data_pooled = BufferPool::acquire(len);
                } else {
                    data_pooled.resize(len);
                }
                recv_stream.read_exact(data_pooled.as_mut_slice()).await?;

                let msg = TunnelMessage::decode(data_pooled.as_slice())
                    .ok_or_else(|| "Failed to decode message".to_string())?;

                match msg {
                    TunnelMessage::DataChunk { data, fin, .. } => {
                        if !data.is_empty() {
                            tcp_write.write_all(&data).await?;
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

        counter!("maluwaf.vpn.client.tcp.streams").increment(1);

        let result = tokio::try_join!(tcp_to_quic, quic_to_tcp);

        let _ = send_stream.finish();

        counter!("maluwaf.vpn.client.tcp.streams_closed").increment(1);

        result.map(|_| ())
    }

    async fn start_udp(&self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if !self.datagram_caps.supported {
            return Err("UDP requires datagram support but it's not available".into());
        }

        let socket = UdpSocket::bind(self.mapping.local_addr).await?;
        let local_addr = socket.local_addr()?;

        tracing::info!(
            "UDP listener started on {} -> remote:{}",
            local_addr,
            self.mapping.remote_port
        );

        let (mut send_stream, mut recv_stream) = self
            .connection
            .open_bi()
            .await
            .map_err(|e| format!("Failed to open stream: {}", e))?;

        let open_msg = TunnelMessage::UdpTunnelOpen {
            identifier: self.mapping.identifier.clone(),
            port: self.mapping.remote_port,
        };
        write_message(&mut send_stream, &open_msg).await?;

        let response = read_message_default(&mut recv_stream).await?;

        match response {
            TunnelMessage::UdpTunnelOpenAck {
                success, message, ..
            } => {
                if !success {
                    return Err(
                        format!("UDP tunnel open failed: {}", message.unwrap_or_default()).into(),
                    );
                }
            }
            _ => return Err("Unexpected response to UdpTunnelOpen".into()),
        }

        let socket = Arc::new(socket);
        let connection = self.connection.clone();
        let identifier = self.mapping.identifier.clone();
        let max_size = self.datagram_caps.max_size;
        let shutdown_rx = self.shutdown_tx.subscribe();

        let tracker = Arc::new(UdpClientTracker::new());

        let socket_recv = socket.clone();
        let identifier_recv = identifier.clone();
        let conn_send = connection.clone();
        let tracker_recv = tracker.clone();

        tokio::spawn(async move {
            Self::udp_recv_loop(
                socket_recv,
                conn_send,
                identifier_recv,
                max_size,
                tracker_recv,
                shutdown_rx,
            )
            .await;
        });

        let socket_send = socket.clone();
        let identifier_send = identifier.clone();
        let shutdown_rx_send = self.shutdown_tx.subscribe();
        let tracker_send = tracker.clone();

        tokio::spawn(async move {
            Self::udp_send_loop(
                socket_send,
                connection,
                identifier_send,
                tracker_send,
                shutdown_rx_send,
            )
            .await;
        });

        let tracker_cleanup = tracker.clone();
        let shutdown_rx_cleanup = self.shutdown_tx.subscribe();
        tokio::spawn(async move {
            let mut interval =
                tokio::time::interval(Duration::from_secs(UDP_CLEANUP_INTERVAL_SECS));
            let mut shutdown = shutdown_rx_cleanup;

            loop {
                tokio::select! {
                    _ = interval.tick() => {
                        tracker_cleanup.cleanup_expired();
                    }
                    _ = shutdown.recv() => {
                        break;
                    }
                }
            }
        });

        counter!("maluwaf.vpn.client.udp.tunnels").increment(1);

        Ok(())
    }

    async fn udp_recv_loop(
        socket: Arc<UdpSocket>,
        connection: Connection,
        identifier: String,
        max_size: usize,
        tracker: Arc<UdpClientTracker>,
        mut shutdown_rx: broadcast::Receiver<()>,
    ) {
        let mut sequence_counter: u64 = 0;
        let recv_buffer_size = max_size.max(1200);
        let mut recv_pooled = BufferPool::acquire(recv_buffer_size);

        loop {
            tokio::select! {
                recv_result = socket.recv_from(recv_pooled.as_mut_slice()) => {
                    match recv_result {
                        Ok((len, client_addr)) => {
                            let data = &recv_pooled.as_mut_slice()[..len];

                            if !tracker.register(client_addr) {
                                tracing::warn!(
                                    "UDP client map full, dropping packet from {}",
                                    client_addr
                                );
                                counter!("maluwaf.vpn.client.udp.client_dropped").increment(1);
                                continue;
                            }

                            let msg = DatagramMessage::new(
                                identifier.clone(),
                                sequence_counter,
                                data.to_vec(),
                                0,
                                client_addr.to_string(),
                            );

                            sequence_counter = sequence_counter.wrapping_add(1);

                            if let Ok(encoded) = msg.encode() {
                                if encoded.len() <= max_size {
                                    match connection.send_datagram(encoded.into()) { Err(e) => {
                                        tracing::debug!("Failed to send UDP datagram: {}", e);
                                    } _ => {
                                        counter!("maluwaf.vpn.client.udp.packets_sent").increment(1);
                                    }}
                                }
                            }
                        }
                        Err(e) => {
                            tracing::debug!("UDP recv error: {}", e);
                        }
                    }
                }
                _ = shutdown_rx.recv() => {
                    tracing::info!("UDP recv loop shutting down");
                    break;
                }
            }
        }
    }

    async fn udp_send_loop(
        socket: Arc<UdpSocket>,
        connection: Connection,
        identifier: String,
        tracker: Arc<UdpClientTracker>,
        mut shutdown_rx: broadcast::Receiver<()>,
    ) {
        loop {
            tokio::select! {
                datagram_result = connection.read_datagram() => {
                    match datagram_result {
                        Ok(data) => {
                            if let Some(msg) = DatagramMessage::decode(&data) {
                                if msg.identifier != identifier {
                                    continue;
                                }

                                let target_client = tracker.lookup_by_source(&msg.source_addr);

                                if let Some(client_addr) = target_client {
                                    if let Err(e) = socket.send_to(&msg.data, client_addr).await {
                                        tracing::debug!("Failed to send UDP to client {}: {}", client_addr, e);
                                    } else {
                                        counter!("maluwaf.vpn.client.udp.packets_recv").increment(1);
                                    }
                                } else {
                                    tracing::trace!(
                                        "Dropping UDP packet for unknown client from {}",
                                        msg.source_addr
                                    );
                                }
                            }
                        }
                        Err(e) => {
                            tracing::trace!("Datagram read error: {}", e);
                            break;
                        }
                    }
                }
                _ = shutdown_rx.recv() => {
                    tracing::info!("UDP send loop shutting down");
                    break;
                }
            }
        }
    }

    pub fn stop(&self) {
        let _ = self.shutdown_tx.send(());
    }
}
