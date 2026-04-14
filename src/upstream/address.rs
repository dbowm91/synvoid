use parking_lot::Mutex;
use quinn::{RecvStream, SendStream};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;
use thiserror::Error;
use tokio::net::{TcpStream, UnixStream};

#[derive(Error, Debug)]
pub enum UpstreamError {
    #[error("Invalid address: {0}")]
    InvalidAddress(String),
    #[error("Failed to parse socket address: {0}")]
    ParseError(#[from] std::net::AddrParseError),
    #[error("Failed to connect to upstream: {0}")]
    ConnectionError(String),
    #[error("Unix socket not found: {0}")]
    SocketNotFound(PathBuf),
}

#[derive(Clone, Debug)]
pub enum UpstreamAddress {
    Tcp(SocketAddr),
    Unix(PathBuf),
    QuicTunnel { peer: String, port: u16 },
}

impl UpstreamAddress {
    pub fn parse(url_or_path: &str) -> Result<Self, UpstreamError> {
        let trimmed = url_or_path.trim();

        if trimmed.starts_with("quictunnel://") || trimmed.starts_with("quictunnel:") {
            let rest = trimmed
                .trim_start_matches("quictunnel://")
                .trim_start_matches("quictunnel:");

            if let Some(colon_pos) = rest.rfind(':') {
                let peer = rest[..colon_pos].to_string();
                let port_str = &rest[colon_pos + 1..];
                if let Ok(port) = port_str.parse::<u16>() {
                    return Ok(UpstreamAddress::QuicTunnel { peer, port });
                }
            }
            return Err(UpstreamError::InvalidAddress(format!(
                "Invalid quictunnel format: {} (expected quictunnel:peer:port",
                trimmed
            )));
        }

        if trimmed.starts_with("http+unix://") || trimmed.starts_with("http+unix:") {
            let path = trimmed
                .trim_start_matches("http+unix://")
                .trim_start_matches("http+unix:");
            return Ok(UpstreamAddress::Unix(PathBuf::from(path)));
        }

        if trimmed.starts_with("unix://") || trimmed.starts_with("unix:") {
            let path = trimmed
                .trim_start_matches("unix://")
                .trim_start_matches("unix:");
            return Ok(UpstreamAddress::Unix(PathBuf::from(path)));
        }

        if trimmed.starts_with('/') || trimmed.starts_with("./") {
            return Ok(UpstreamAddress::Unix(PathBuf::from(trimmed)));
        }

        if trimmed.starts_with("http://") || trimmed.starts_with("https://") {
            let without_scheme = trimmed
                .trim_start_matches("https://")
                .trim_start_matches("http://");

            if let Some(slash_pos) = without_scheme.find('/') {
                let host_port = &without_scheme[..slash_pos];
                let _path = &without_scheme[slash_pos..];

                if let Ok(addr) = host_port.parse::<SocketAddr>() {
                    return Ok(UpstreamAddress::Tcp(addr));
                }

                if let Some(port) = host_port.rfind(':') {
                    let host = &host_port[..port];
                    let port_str = &host_port[port + 1..];
                    if let Ok(port) = port_str.parse::<u16>() {
                        let addr = format!("{}:{}", host, port);
                        if let Ok(socket_addr) = addr.parse::<SocketAddr>() {
                            return Ok(UpstreamAddress::Tcp(socket_addr));
                        }
                    }
                }
            }

            if let Ok(addr) = trimmed.parse::<SocketAddr>() {
                return Ok(UpstreamAddress::Tcp(addr));
            }
        }

        if let Ok(addr) = trimmed.parse::<SocketAddr>() {
            return Ok(UpstreamAddress::Tcp(addr));
        }

        Err(UpstreamError::InvalidAddress(url_or_path.to_string()))
    }

    pub async fn connect_tcp_stream(&self) -> Result<TcpStream, UpstreamError> {
        match self {
            UpstreamAddress::Tcp(addr) => TcpStream::connect(addr)
                .await
                .map_err(|e| UpstreamError::ConnectionError(e.to_string())),
            UpstreamAddress::Unix(_) => Err(UpstreamError::ConnectionError(
                "Use connect_unix_stream for Unix sockets".to_string(),
            )),
            UpstreamAddress::QuicTunnel { .. } => Err(UpstreamError::ConnectionError(
                "Use QUIC tunnel proxy for quictunnel addresses".to_string(),
            )),
        }
    }

    pub async fn connect_quictunnel_stream(
        &self,
        runtime: &crate::tunnel::quic::runtime::QuicRuntime,
    ) -> Result<(quinn::SendStream, quinn::RecvStream), UpstreamError> {
        match self {
            UpstreamAddress::QuicTunnel { peer, port } => {
                let identifier = format!("port-{}", port);

                match runtime.open_tunnel_stream_to_peer(peer, &identifier).await {
                    Ok(streams) => Ok(streams),
                    Err(e) => Err(UpstreamError::ConnectionError(e.to_string())),
                }
            }
            _ => Err(UpstreamError::ConnectionError(
                "Not a QUIC tunnel address".to_string(),
            )),
        }
    }

    pub async fn connect_quictunnel_tcp(
        &self,
        runtime: &crate::tunnel::quic::runtime::QuicRuntime,
    ) -> Result<QuicTunnelStream, UpstreamError> {
        match self {
            UpstreamAddress::QuicTunnel { peer, port } => {
                let identifier = format!("port-{}", port);

                let (send, recv) = runtime
                    .open_tunnel_stream_to_peer(peer, &identifier)
                    .await
                    .map_err(|e| UpstreamError::ConnectionError(e.to_string()))?;

                Ok(QuicTunnelStream {
                    send,
                    recv,
                    peer: peer.clone(),
                    port: *port,
                })
            }
            _ => Err(UpstreamError::ConnectionError(
                "Not a QUIC tunnel address".to_string(),
            )),
        }
    }

    pub async fn connect_unix_stream(&self) -> Result<UnixStream, UpstreamError> {
        match self {
            UpstreamAddress::Tcp(_) => Err(UpstreamError::ConnectionError(
                "Use connect_tcp_stream for TCP sockets".to_string(),
            )),
            UpstreamAddress::Unix(path) => {
                if !path.exists() {
                    tracing::warn!("Unix socket not found: {}", path.display());
                }
                UnixStream::connect(path).await.map_err(|e| {
                    if e.kind() == std::io::ErrorKind::NotFound {
                        UpstreamError::SocketNotFound(path.clone())
                    } else {
                        UpstreamError::ConnectionError(e.to_string())
                    }
                })
            }
            UpstreamAddress::QuicTunnel { .. } => Err(UpstreamError::ConnectionError(
                "Use QUIC tunnel proxy for quictunnel addresses".to_string(),
            )),
        }
    }

    pub fn is_unix(&self) -> bool {
        matches!(self, UpstreamAddress::Unix(_))
    }

    pub fn is_quictunnel(&self) -> bool {
        matches!(self, UpstreamAddress::QuicTunnel { .. })
    }

    pub fn path(&self) -> Option<&PathBuf> {
        match self {
            UpstreamAddress::Unix(p) => Some(p),
            UpstreamAddress::Tcp(_) => None,
            UpstreamAddress::QuicTunnel { .. } => None,
        }
    }

    pub fn tcp_addr(&self) -> Option<SocketAddr> {
        match self {
            UpstreamAddress::Tcp(a) => Some(*a),
            UpstreamAddress::Unix(_) => None,
            UpstreamAddress::QuicTunnel { .. } => None,
        }
    }

    pub fn quictunnel_info(&self) -> Option<(&str, u16)> {
        match self {
            UpstreamAddress::QuicTunnel { peer, port } => Some((peer.as_str(), *port)),
            _ => None,
        }
    }
}

#[derive(Clone)]
pub struct SocketErrorTracker {
    errors: Arc<Mutex<HashMap<PathBuf, SocketErrorState>>>,
}

#[derive(Clone)]
struct SocketErrorState {
    last_error_time: Instant,
    consecutive_errors: u32,
    last_logged: Instant,
}

impl SocketErrorTracker {
    pub fn new() -> Self {
        Self {
            errors: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    pub fn should_log_error(&self, path: &std::path::Path) -> bool {
        let mut errors = self.errors.lock();
        let state = errors
            .entry(path.to_path_buf())
            .or_insert(SocketErrorState {
                last_error_time: Instant::now(),
                consecutive_errors: 0,
                last_logged: Instant::now(),
            });

        state.consecutive_errors += 1;
        state.last_error_time = Instant::now();

        let should_log = match state.consecutive_errors {
            1 => true,
            2 => true,
            3 => true,
            n if n <= 10 => state.last_logged.elapsed().as_secs() >= 30,
            n if n <= 30 => state.last_logged.elapsed().as_secs() >= 60,
            n if n <= 60 => state.last_logged.elapsed().as_secs() >= 300,
            _ => state.last_logged.elapsed().as_secs() >= 600,
        };

        if should_log {
            state.last_logged = Instant::now();
        }

        should_log
    }

    pub fn record_success(&self, path: &PathBuf) {
        let mut errors = self.errors.lock();
        if let Some(state) = errors.get_mut(path) {
            state.consecutive_errors = 0;
        }
    }

    pub fn clear(&self, path: &PathBuf) {
        let mut errors = self.errors.lock();
        errors.remove(path);
    }
}

impl Default for SocketErrorTracker {
    fn default() -> Self {
        Self::new()
    }
}

pub struct QuicTunnelStream {
    pub send: SendStream,
    pub recv: RecvStream,
    pub peer: String,
    pub port: u16,
}

impl QuicTunnelStream {
    pub fn into_split(self) -> (SendStream, RecvStream) {
        (self.send, self.recv)
    }
}
