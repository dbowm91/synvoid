use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

#[cfg(target_os = "linux")]
use nix::cmsg_space;
#[cfg(target_os = "linux")]
use nix::sys::socket::{recvmsg, ControlMessageOwned, MsgFlags};

use metrics::counter;
use parking_lot::RwLock;
use tokio::net::UdpSocket;
use tokio::sync::mpsc;
use tokio_dstip::TcpListenerWithDst;

use crate::config::dns::DnsAnycastConfig;
use crate::dns::platform::AnycastSocketPlatform;

#[derive(Debug, Clone)]
pub struct BoundSocket {
    pub socket: Arc<UdpSocket>,
    pub local_addr: SocketAddr,
    pub ip: IpAddr,
    pub healthy: bool,
    pub last_check: Instant,
    pub query_count: Arc<AtomicU64>,
    pub error_count: Arc<AtomicU64>,
}

pub struct BoundTcpListener {
    pub listener: TcpListenerWithDst,
    pub local_addr: SocketAddr,
    pub ip: IpAddr,
    pub healthy: bool,
    pub connection_count: Arc<AtomicU64>,
    pub error_count: Arc<AtomicU64>,
}

#[derive(Debug)]
pub struct AnycastTcpConnection {
    pub stream: tokio::net::TcpStream,
    pub peer_addr: SocketAddr,
    pub dest_ip: IpAddr,
}

#[derive(Debug, Clone)]
pub struct AnycastPacketInfo {
    pub data: Vec<u8>,
    pub src: SocketAddr,
    pub dest_ip: IpAddr,
}

pub struct AnycastSocketManager {
    sockets: Vec<BoundSocket>,
    tcp_listeners: Vec<Arc<BoundTcpListener>>,
    platform: Arc<dyn AnycastSocketPlatform>,
    config: DnsAnycastConfig,
    health_status: Arc<RwLock<HashMap<IpAddr, bool>>>,
    health_tx: Option<mpsc::Sender<AnycastHealthUpdate>>,
    health_check_domain: String,
}

#[derive(Debug, Clone)]
pub struct AnycastHealthUpdate {
    pub ip: IpAddr,
    pub healthy: bool,
    pub query_count: u64,
    pub error_count: u64,
    pub latency_ms: Option<u64>,
}

impl AnycastSocketManager {
    pub async fn new(
        config: &DnsAnycastConfig,
        platform: Arc<dyn AnycastSocketPlatform>,
    ) -> Result<Self, String> {
        let mut sockets = Vec::new();
        let mut tcp_listeners = Vec::new();

        for addr_str in &config.bind_addresses {
            let addr: IpAddr = addr_str
                .parse()
                .map_err(|e| format!("Invalid bind address '{}': {}", addr_str, e))?;

            let socket_addr = SocketAddr::new(addr, config.port);

            let socket = UdpSocket::bind(socket_addr)
                .await
                .map_err(|e| format!("Failed to bind UDP to {}: {}", socket_addr, e))?;

            if config.use_pktinfo {
                if let Err(e) = platform.enable_pktinfo(&socket) {
                    tracing::warn!("Failed to enable PKTINFO on {}: {}", socket_addr, e);
                }
            }

            let bound_socket = BoundSocket {
                socket: Arc::new(socket),
                local_addr: socket_addr,
                ip: addr,
                healthy: true,
                last_check: Instant::now(),
                query_count: Arc::new(AtomicU64::new(0)),
                error_count: Arc::new(AtomicU64::new(0)),
            };

            tracing::info!("Anycast UDP socket bound to {}", socket_addr);
            sockets.push(bound_socket);

            let tcp_listener = TcpListenerWithDst::bind(socket_addr)
                .await
                .map_err(|e| format!("Failed to bind TCP to {}: {}", socket_addr, e))?;

            let bound_tcp = BoundTcpListener {
                listener: tcp_listener,
                local_addr: socket_addr,
                ip: addr,
                healthy: true,
                connection_count: Arc::new(AtomicU64::new(0)),
                error_count: Arc::new(AtomicU64::new(0)),
            };

            tracing::info!("Anycast TCP listener bound to {}", socket_addr);
            tcp_listeners.push(Arc::new(bound_tcp));
        }

        if sockets.is_empty() {
            return Err("No sockets bound for anycast".to_string());
        }

        let health_status: HashMap<IpAddr, bool> = sockets.iter().map(|s| (s.ip, true)).collect();

        Ok(Self {
            sockets,
            tcp_listeners,
            platform,
            config: config.clone(),
            health_status: Arc::new(RwLock::new(health_status)),
            health_tx: None,
            health_check_domain: config.health_check_domain.clone(),
        })
    }

    pub fn set_health_sender(&mut self, tx: mpsc::Sender<AnycastHealthUpdate>) {
        self.health_tx = Some(tx);
    }

    pub fn get_bound_ips(&self) -> Vec<IpAddr> {
        self.sockets.iter().map(|s| s.ip).collect()
    }

    pub fn get_bound_addresses(&self) -> Vec<SocketAddr> {
        self.sockets.iter().map(|s| s.local_addr).collect()
    }

    pub fn get_tcp_listeners(&self) -> &[Arc<BoundTcpListener>] {
        &self.tcp_listeners
    }

    pub fn get_tcp_listener_addresses(&self) -> Vec<SocketAddr> {
        self.tcp_listeners.iter().map(|l| l.local_addr).collect()
    }

    pub fn supports_tcp_pktinfo(&self) -> bool {
        self.platform.supports_tcp_pktinfo()
    }

    pub async fn accept_tcp(&self) -> Result<AnycastTcpConnection, String> {
        for listener in &self.tcp_listeners {
            match listener.listener.accept_with_dst().await {
                Ok((stream, peer, dst_ip)) => {
                    listener.connection_count.fetch_add(1, Ordering::Relaxed);
                    counter!("dns_anycast_tcp_connections_total").increment(1);
                    return Ok(AnycastTcpConnection {
                        stream,
                        peer_addr: peer,
                        dest_ip: dst_ip,
                    });
                }
                Err(e) => {
                    tracing::debug!("TCP accept failed on {}: {}", listener.local_addr, e);
                    listener.error_count.fetch_add(1, Ordering::Relaxed);
                }
            }
        }

        counter!("dns_anycast_tcp_accept_errors_total").increment(1);
        Err("All TCP anycast listeners failed to accept".to_string())
    }

    pub fn supports_pktinfo(&self) -> bool {
        self.platform.supports_pktinfo()
    }

    pub fn platform_name(&self) -> &'static str {
        self.platform.platform_name()
    }

    pub fn is_healthy(&self, ip: &IpAddr) -> bool {
        *self.health_status.read().get(ip).unwrap_or(&false)
    }

    pub fn get_healthy_ips(&self) -> Vec<IpAddr> {
        let status = self.health_status.read();
        status
            .iter()
            .filter(|(_, healthy)| **healthy)
            .map(|(ip, _)| *ip)
            .collect()
    }

    pub async fn start_health_monitor(&self, interval_secs: u64) {
        let health_tx = self.health_tx.clone();
        let health_status = self.health_status.clone();
        let sockets = self.sockets.clone();
        let health_check_domain = self.health_check_domain.clone();
        let port = self.config.port;

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(interval_secs));

            loop {
                interval.tick().await;

                for socket in &sockets {
                    let (healthy, latency) = Self::check_socket_health_async(
                        &socket.socket,
                        socket.ip,
                        port,
                        &health_check_domain,
                    )
                    .await;

                    {
                        let mut status = health_status.write();
                        status.insert(socket.ip, healthy);
                    }

                    if let Some(ref tx) = health_tx {
                        let update = AnycastHealthUpdate {
                            ip: socket.ip,
                            healthy,
                            query_count: socket.query_count.load(Ordering::Relaxed),
                            error_count: socket.error_count.load(Ordering::Relaxed),
                            latency_ms: latency,
                        };

                        let _ = tx.send(update).await;
                    }

                    if !healthy {
                        tracing::warn!("Anycast socket {} is unhealthy", socket.local_addr);
                    }
                }

                tracing::debug!("Anycast health check: {:?}", health_status.read().clone());
            }
        });
    }

    async fn check_socket_health_async(
        socket: &UdpSocket,
        anycast_ip: IpAddr,
        port: u16,
        health_check_domain: &str,
    ) -> (bool, Option<u64>) {
        let start = Instant::now();

        let query_id = Self::rand_u16();

        let query_packet = match Self::build_health_check_query(query_id, health_check_domain) {
            Some(packet) => packet,
            None => return (false, None),
        };

        let dest_addr = SocketAddr::new(anycast_ip, port);

        if let Err(e) = socket.send_to(&query_packet, dest_addr).await {
            tracing::debug!("Health check send failed for {}: {}", anycast_ip, e);
            return (false, None);
        }

        let mut buf = [0u8; 512];
        let mut iterations = 0;
        let max_iterations = 50;

        while iterations < max_iterations {
            match tokio::time::timeout(Duration::from_millis(20), socket.recv_from(&mut buf)).await
            {
                Ok(Ok((len, src))) => {
                    if (src.ip() == anycast_ip
                        || src.ip() == IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
                        && len >= 12
                    {
                        let response_id = u16::from_be_bytes([buf[0], buf[1]]);
                        if response_id == query_id {
                            let flags = u16::from_be_bytes([buf[2], buf[3]]);
                            let is_response = (flags & 0x8000) != 0;
                            if is_response {
                                let latency = start.elapsed().as_millis() as u64;
                                tracing::debug!(
                                        "Health check received valid response for {}: id={}, latency={}ms",
                                        anycast_ip,
                                        response_id,
                                        latency
                                    );
                                return (true, Some(latency));
                            }
                        }
                    }
                }
                Ok(Err(_)) => {
                    break;
                }
                Err(_) => {
                    iterations += 1;
                }
            }
        }

        tracing::debug!(
            "Health check timed out or invalid response for {}",
            anycast_ip
        );
        (false, None)
    }

    pub fn build_health_check_query(query_id: u16, domain: &str) -> Option<Vec<u8>> {
        let mut packet = Vec::new();

        packet.extend_from_slice(&query_id.to_be_bytes());

        packet.extend_from_slice(&0x0100u16.to_be_bytes());

        packet.extend_from_slice(&0x0001u16.to_be_bytes());

        packet.extend_from_slice(&0x0000u16.to_be_bytes());

        packet.extend_from_slice(&0x0000u16.to_be_bytes());

        packet.extend_from_slice(&0x0000u16.to_be_bytes());

        let labels: Vec<&str> = domain.trim_end_matches('.').split('.').collect();
        for label in &labels {
            if label.is_empty() || label.len() > 63 {
                return None;
            }
            packet.push(label.len() as u8);
            packet.extend_from_slice(label.as_bytes());
        }
        packet.push(0);

        packet.extend_from_slice(&0x0001u16.to_be_bytes());

        packet.extend_from_slice(&0x0001u16.to_be_bytes());

        Some(packet)
    }

    fn rand_u16() -> u16 {
        use std::time::{SystemTime, UNIX_EPOCH};
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .subsec_nanos();
        (nanos as u16) ^ ((nanos >> 16) as u16)
    }

    pub async fn recv_from(&self, buf: &mut [u8]) -> Result<(usize, SocketAddr, IpAddr), String> {
        let sockets = self.sockets.clone();
        let platform = self.platform.clone();

        let num_sockets = sockets.len();

        match num_sockets {
            0 => Err("No sockets available".to_string()),
            1 => Self::recv_from_single(&sockets[0], platform, buf).await,
            _ => {
                let mut errors = Vec::new();

                for socket in &sockets {
                    let mut buf_4096 = [0u8; 4096];
                    match socket.socket.recv_from(&mut buf_4096).await {
                        Ok((len, src)) => {
                            let dest_ip = if platform.supports_pktinfo() {
                                Self::get_destination_sync(&socket.socket, platform.clone())
                                    .unwrap_or_else(|| {
                                        Self::infer_destination_ip_from_src(&src, socket.ip)
                                    })
                            } else {
                                socket.ip
                            };

                            if len > buf.len() {
                                return Err(format!("Packet too large: {} > {}", len, buf.len()));
                            }

                            buf[..len].copy_from_slice(&buf_4096[..len]);
                            socket.query_count.fetch_add(1, Ordering::Relaxed);
                            counter!("dns_anycast_queries_total").increment(1);
                            return Ok((len, src, dest_ip));
                        }
                        Err(e) => {
                            tracing::debug!("recv_from on {} failed: {}", socket.local_addr, e);
                            errors.push(format!("{}: {}", socket.local_addr, e));
                        }
                    }
                }

                counter!("dns_anycast_errors_total").increment(1);
                Err(format!("All anycast sockets failed: {}", errors.join("; ")))
            }
        }
    }

    async fn recv_from_single(
        socket: &BoundSocket,
        platform: Arc<dyn AnycastSocketPlatform>,
        buf: &mut [u8],
    ) -> Result<(usize, SocketAddr, IpAddr), String> {
        let mut buf_4096 = [0u8; 4096];
        let (len, src) = socket
            .socket
            .recv_from(&mut buf_4096)
            .await
            .map_err(|e| format!("{}: {}", socket.local_addr, e))?;

        if len > buf.len() {
            return Err(format!("Packet too large: {} > {}", len, buf.len()));
        }

        let dest_ip = if platform.supports_pktinfo() {
            Self::get_destination_sync(&socket.socket, platform)
                .unwrap_or_else(|| Self::infer_destination_ip_from_src(&src, socket.ip))
        } else {
            socket.ip
        };

        buf[..len].copy_from_slice(&buf_4096[..len]);
        socket.query_count.fetch_add(1, Ordering::Relaxed);
        counter!("dns_anycast_queries_total").increment(1);

        Ok((len, src, dest_ip))
    }

    fn infer_destination_ip_from_src(src: &SocketAddr, fallback_ip: IpAddr) -> IpAddr {
        match (src, fallback_ip) {
            (SocketAddr::V4(_src), IpAddr::V4(_)) => IpAddr::V4(Ipv4Addr::new(0, 0, 0, 0)),
            (SocketAddr::V6(_src), IpAddr::V6(_)) => {
                IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 0))
            }
            _ => fallback_ip,
        }
    }

    #[cfg(target_os = "linux")]
    fn get_destination_sync(
        socket: &UdpSocket,
        _platform: Arc<dyn AnycastSocketPlatform>,
    ) -> Option<IpAddr> {
        use nix::sys::socket::SockaddrIn;

        let fd = socket.as_raw_fd();
        let mut buf = [0u8; 1];
        let mut iov = [std::io::IoSliceMut::new(&mut buf)];
        let mut cmsg_buffer = cmsg_space!([nix::libc::in_pktinfo; 2]);

        let msg =
            match recvmsg::<SockaddrIn>(fd, &mut iov, Some(&mut cmsg_buffer), MsgFlags::MSG_PEEK) {
                Ok(m) => m,
                Err(_) => return None,
            };

        if let Ok(cmsg_iter) = msg.cmsgs() {
            for cmsg in cmsg_iter {
                match cmsg {
                    ControlMessageOwned::Ipv4PacketInfo(pktinfo) => {
                        let addr =
                            IpAddr::from(Ipv4Addr::from(pktinfo.ipi_addr.s_addr.to_ne_bytes()));
                        return Some(addr);
                    }
                    ControlMessageOwned::Ipv6PacketInfo(pktinfo) => {
                        let addr = IpAddr::from(Ipv6Addr::from(pktinfo.ipi6_addr.s6_addr));
                        return Some(addr);
                    }
                    _ => continue,
                }
            }
        }

        None
    }

    #[cfg(not(target_os = "linux"))]
    fn get_destination_sync(
        _socket: &UdpSocket,
        _platform: Arc<dyn AnycastSocketPlatform>,
    ) -> Option<IpAddr> {
        None
    }

    pub async fn send_to(
        &self,
        data: &[u8],
        dest: SocketAddr,
        orig_dest: IpAddr,
    ) -> Result<usize, String> {
        let socket = self.select_socket_for_destination(orig_dest)?;

        socket
            .socket
            .send_to(data, dest)
            .await
            .map_err(|e| format!("Send failed: {}", e))
    }

    fn select_socket_for_destination(&self, dest_ip: IpAddr) -> Result<&BoundSocket, String> {
        for socket in &self.sockets {
            match (&socket.ip, &dest_ip) {
                (IpAddr::V4(s), IpAddr::V4(d)) => {
                    if s.octets() == d.octets() {
                        return Ok(socket);
                    }
                }
                (IpAddr::V6(s), IpAddr::V6(d)) => {
                    if s.segments() == d.segments() {
                        return Ok(socket);
                    }
                }
                _ => continue,
            }
        }

        if let Some(first) = self.sockets.first() {
            tracing::debug!(
                "No exact match for dest {} in anycast, using first socket {}",
                dest_ip,
                first.local_addr
            );
            Ok(first)
        } else {
            Err("No anycast sockets available".to_string())
        }
    }

    pub fn get_socket_for_ip(&self, ip: &IpAddr) -> Option<Arc<UdpSocket>> {
        for socket in &self.sockets {
            if socket.ip == *ip {
                return Some(socket.socket.clone());
            }
        }
        None
    }

    pub fn record_query(&self, ip: &IpAddr) {
        for socket in &self.sockets {
            if socket.ip == *ip {
                socket.query_count.fetch_add(1, Ordering::Relaxed);
                return;
            }
        }
    }

    pub fn record_error(&self, ip: &IpAddr) {
        for socket in &self.sockets {
            if socket.ip == *ip {
                socket.error_count.fetch_add(1, Ordering::Relaxed);
                return;
            }
        }
    }

    pub async fn connect_to_client(
        &self,
        client_addr: SocketAddr,
        bind_ip: IpAddr,
    ) -> Result<tokio::net::TcpStream, String> {
        let socket = tokio::net::TcpSocket::new_v4()
            .map_err(|e| format!("Failed to create TCP socket: {}", e))?;

        socket
            .set_reuseaddr(true)
            .map_err(|e| format!("Failed to set SO_REUSEADDR: {}", e))?;

        let bind_addr = SocketAddr::new(bind_ip, 0);
        socket
            .bind(bind_addr)
            .map_err(|e| format!("Failed to bind to {}: {}", bind_addr, e))?;

        socket
            .connect(client_addr)
            .await
            .map_err(|e| format!("Failed to connect to {}: {}", client_addr, e))
    }
}
