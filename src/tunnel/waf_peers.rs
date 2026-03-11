use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{broadcast, Mutex as TokioMutex};
use tokio_rustls::TlsAcceptor;
use metrics::{counter, gauge};
use parking_lot::Mutex;
use subtle::ConstantTimeEq;
use rustls::{ServerConfig, RootCertStore};

use crate::config::main::{TunnelWafPeersConfig, TunnelPeerConfig};
use crate::tunnel::TunnelSession;

const MAX_MESSAGE_SIZE: usize = 64 * 1024;

const AUTH_RATE_LIMIT_WINDOW_SECS: u64 = 60;
const AUTH_RATE_LIMIT_MAX_ATTEMPTS: u32 = 10;

struct AuthAttempt {
    attempts: u32,
    window_start: Instant,
}

pub struct PeerAuthRateLimiter {
    attempts: Arc<Mutex<HashMap<String, AuthAttempt>>>,
}

impl Clone for PeerAuthRateLimiter {
    fn clone(&self) -> Self {
        Self {
            attempts: self.attempts.clone(),
        }
    }
}

impl PeerAuthRateLimiter {
    pub fn new() -> Self {
        Self {
            attempts: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    fn cleanup(&self) {
        let mut attempts = self.attempts.lock();
        let now = Instant::now();
        attempts.retain(|_, attempt| {
            now.duration_since(attempt.window_start) <= Duration::from_secs(AUTH_RATE_LIMIT_WINDOW_SECS * 2)
        });
    }

    pub fn check(&self, ip: &str) -> bool {
        let mut attempts = self.attempts.lock();
        
        static CLEANUP_COUNTER: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);
        if (CLEANUP_COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed) + 1) % 100 == 0 {
            drop(attempts);
            self.cleanup();
            attempts = self.attempts.lock();
        }
        
        let now = Instant::now();
        
        if let Some(attempt) = attempts.get_mut(ip) {
            if now.duration_since(attempt.window_start) > Duration::from_secs(AUTH_RATE_LIMIT_WINDOW_SECS) {
                attempt.attempts = 1;
                attempt.window_start = now;
                return true;
            }
            
            if attempt.attempts >= AUTH_RATE_LIMIT_MAX_ATTEMPTS {
                counter!("rustwaf.tunnel.waf_peers.rate_limited").increment(1);
                tracing::warn!("Peer auth rate limited for IP: {}", ip);
                return false;
            }
            
            attempt.attempts += 1;
            return true;
        }
        
        attempts.insert(ip.to_string(), AuthAttempt {
            attempts: 1,
            window_start: now,
        });
        true
    }
}

impl Default for PeerAuthRateLimiter {
    fn default() -> Self {
        Self::new()
    }
}

pub struct WafPeerServer {
    config: TunnelWafPeersConfig,
    peers: Arc<DashMap<String, PeerConnection>>,
    shutdown_tx: broadcast::Sender<()>,
    auth_rate_limiter: PeerAuthRateLimiter,
}

#[derive(Clone)]
pub struct PeerConnection {
    pub id: String,
    pub address: String,
    pub session_id: String,
    pub connected_at: std::time::Instant,
    pub stream: Arc<Mutex<Option<tokio::net::TcpStream>>>,
}

impl WafPeerServer {
    pub fn new(config: TunnelWafPeersConfig) -> Self {
        let (shutdown_tx, _) = broadcast::channel(1);
        
        Self {
            config,
            peers: Arc::new(DashMap::new()),
            shutdown_tx,
            auth_rate_limiter: PeerAuthRateLimiter::new(),
        }
    }

    fn build_tls_config(&self) -> Option<ServerConfig> {
        let cert_path = self.config.client_cert_path.as_ref()?;
        let key_path = self.config.client_key_path.as_ref()?;
        
        let cert_file = std::fs::File::open(cert_path).ok()?;
        let key_file = std::fs::File::open(key_path).ok()?;
        
        let mut cert_reader = std::io::BufReader::new(cert_file);
        let certs_result = rustls_pemfile::certs(&mut cert_reader);
        let certs_vec: Vec<_> = certs_result.filter_map(|r| r.ok()).collect();
        if certs_vec.is_empty() {
            return None;
        }
        
        let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(key_file)).ok().flatten()?;
        
        let mut config = ServerConfig::builder()
            .with_no_client_auth();
        
        if let Some(ca_path) = &self.config.ca_cert_path {
            if let Ok(ca_file) = std::fs::File::open(ca_path) {
                let mut ca_reader = std::io::BufReader::new(ca_file);
                let ca_certs: Vec<_> = rustls_pemfile::certs(&mut ca_reader)
                    .filter_map(|r| r.ok())
                    .collect();
                if !ca_certs.is_empty() {
                    tracing::info!("WAF peer TLS configured with CA cert (mTLS requires rustls 0.24+)");
                } else {
                    tracing::warn!("CA cert file found but no valid certificates, falling back to no client auth");
                }
            } else {
                tracing::warn!("CA cert file not found, falling back to no client auth");
            }
        } else {
            tracing::info!("WAF peer TLS configured (mTLS disabled - no CA cert configured)");
        }
        
        let mut config = config.with_single_cert(certs_vec, key).ok()?;
        
        config.alpn_protocols = vec![b"waf-peer".to_vec()];
        
        Some(config)
    }

    pub async fn start(&mut self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let addr = format!("{}:{}", self.config.bind_address, self.config.port);
        
        tracing::info!("WAF peer server starting on {}", addr);
        
        let listener = TcpListener::bind(&addr).await?;
        
        let tls_config = self.build_tls_config();
        
        if self.config.require_tls && tls_config.is_none() {
            tracing::error!("WAF peer server requires TLS but no certificates configured!");
            return Err("TLS required but certificates not configured".into());
        }
        
        if tls_config.is_some() {
            tracing::info!("WAF peer server using TLS");
        } else {
            tracing::error!("WAF peer server cannot start without TLS - credentials would be sent in plaintext!");
            return Err("TLS is required for secure peer communication".into());
        }
        
        tracing::info!("WAF peer server listening on {}", addr);
        gauge!("rustwaf.tunnel.waf_peers.listeners").set(1.0);

        let shutdown_rx = self.shutdown_tx.subscribe();
        self.accept_loop(listener, shutdown_rx, self.auth_rate_limiter.clone(), tls_config).await;

        Ok(())
    }

    async fn accept_loop(&self, listener: TcpListener, mut shutdown_rx: broadcast::Receiver<()>, rate_limiter: PeerAuthRateLimiter, tls_config: Option<ServerConfig>) {
        loop {
            tokio::select! {
                result = listener.accept() => {
                    match result {
                        Ok((stream, remote_addr)) => {
                            let config = self.config.clone();
                            let peers = self.peers.clone();
                            let rate_limiter = rate_limiter.clone();
                            let tls_config = tls_config.clone();
                            tokio::spawn(async move {
                                if let Err(e) = Self::handle_connection(stream, remote_addr, config, peers, rate_limiter, tls_config).await {
                                    tracing::error!("WAF peer connection error: {}", e);
                                }
                            });
                        }
                        Err(e) => {
                            tracing::error!("WAF peer accept error: {}", e);
                        }
                    }
                }
                _ = shutdown_rx.recv() => {
                    tracing::info!("WAF peer server shutting down");
                    break;
                }
            }
        }
    }

    async fn handle_connection(
        stream: TcpStream,
        remote_addr: std::net::SocketAddr,
        config: TunnelWafPeersConfig,
        peers: Arc<DashMap<String, PeerConnection>>,
        rate_limiter: PeerAuthRateLimiter,
        tls_config: Option<ServerConfig>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let stream = if let Some(tls_cfg) = tls_config {
            let acceptor = TlsAcceptor::from(Arc::new(tls_cfg));
            match acceptor.accept(stream).await {
                Ok(tls_stream) => tokio_rustls::TlsStream::Server(tls_stream),
                Err(e) => {
                    tracing::warn!("TLS handshake failed: {}", e);
                    return Ok(());
                }
            }
        } else {
            let (rd, wr) = tokio::io::split(stream);
            return Self::handle_tcp_connection(rd, wr, remote_addr, config, peers, rate_limiter).await;
        };
        
        let (rd, wr) = tokio::io::split(stream);
        Self::handle_tcp_connection(rd, wr, remote_addr, config, peers, rate_limiter).await
    }

    async fn handle_tcp_connection<R, W>(
        rd: R,
        mut wr: W,
        remote_addr: std::net::SocketAddr,
        config: TunnelWafPeersConfig,
        peers: Arc<DashMap<String, PeerConnection>>,
        rate_limiter: PeerAuthRateLimiter,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>>
    where
        R: tokio::io::AsyncRead + Unpin,
        W: tokio::io::AsyncWrite + Unpin,
    {
        tracing::info!("New WAF peer connection from {}", remote_addr);
        
        let ip_str = remote_addr.ip().to_string();
        if !rate_limiter.check(&ip_str) {
            tracing::warn!("Peer auth rate limited: {}", remote_addr);
            return Ok(());
        }
        
        let session_id = uuid::Uuid::new_v4().to_string();
        
        let mut reader = rd;
        
        let buf = Self::read_message(&mut reader).await?;

        let msg: PeerMessage = match serde_json::from_slice(&buf) {
            Ok(m) => m,
            Err(e) => {
                tracing::warn!("Invalid peer message from {}: {}", remote_addr, e);
                return Ok(());
            }
        };

        match msg {
            PeerMessage::Hello { peer_id, auth_token } => {
                let mut authenticated = false;
                let mut peer_name = String::new();
                
                let remote_ip = remote_addr.ip();
                
                for (name, peer) in &config.peers {
                    if !peer.enabled {
                        continue;
                    }
                    
                    let peer_addr_matches = Self::ip_matches_peer(&peer.address, remote_ip);
                    let token_matches = !peer.auth_token.is_empty() && auth_token.as_bytes().ct_eq(peer.auth_token.as_bytes()).into();
                    
                    if (peer_addr_matches || token_matches) && peer.enabled {
                        authenticated = true;
                        peer_name = name.clone();
                        
                        let response = PeerMessage::HelloAck {
                            session_id: session_id.clone(),
                        };
                        Self::write_message(&mut wr, &response).await?;
                        
                        counter!("rustwaf.tunnel.waf_peers.connected").increment(1);
                        tracing::info!("WAF peer authenticated: {} ({}) from {}", peer_id, peer_name, remote_addr);
                        break;
                    }
                }

                if !authenticated {
                    let error = PeerMessage::AuthFailure {
                        reason: "Invalid peer credentials".to_string(),
                    };
                    Self::write_message(&mut wr, &error).await?;
                    counter!("rustwaf.tunnel.waf_peers.auth_failures").increment(1);
                    tracing::warn!("WAF peer auth failure from {}", remote_addr);
                }
            }
            _ => {}
        }

        Ok(())
    }

    async fn read_message<R: AsyncReadExt + Unpin>(reader: &mut R) -> Result<Vec<u8>, Box<dyn std::error::Error + Send + Sync>> {
        let mut len_buf = [0u8; 4];
        reader.read_exact(&mut len_buf).await
            .map_err(|e| format!("Failed to read message length: {}", e))?;
        
        let len = u32::from_be_bytes(len_buf) as usize;
        if len > MAX_MESSAGE_SIZE {
            return Err(format!("Message too large: {} bytes (max {})", len, MAX_MESSAGE_SIZE).into());
        }

        let mut data = vec![0u8; len];
        reader.read_exact(&mut data).await
            .map_err(|e| format!("Failed to read message: {}", e))?;

        Ok(data)
    }

    async fn write_message<W: AsyncWriteExt + Unpin>(writer: &mut W, msg: &PeerMessage) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let data = serde_json::to_vec(msg)?;
        let len = (data.len() as u32).to_be_bytes();
        writer.write_all(&len).await
            .map_err(|e| format!("Failed to write message length: {}", e))?;
        writer.write_all(&data).await
            .map_err(|e| format!("Failed to write message: {}", e))?;
        Ok(())
    }

    pub async fn connect_to_peer(&self, name: &str, config: &TunnelPeerConfig) -> Result<PeerConnection, Box<dyn std::error::Error + Send + Sync>> {
        tracing::info!("Connecting to WAF peer {} at {}", name, config.address);
        
        let mut stream = TcpStream::connect(&config.address).await?;
        
        let hello = PeerMessage::Hello {
            peer_id: name.to_string(),
            auth_token: config.auth_token.clone(),
        };
        
        Self::write_message(&mut stream, &hello).await?;
        
        let buf = Self::read_message(&mut stream).await?;
        
        let response: PeerMessage = serde_json::from_slice(&buf)?;
        
        match response {
            PeerMessage::HelloAck { session_id } => {
                let connection = PeerConnection {
                    id: name.to_string(),
                    address: config.address.clone(),
                    session_id,
                    connected_at: std::time::Instant::now(),
                    stream: Arc::new(Mutex::new(Some(stream))),
                };
                
                self.peers.insert(name.to_string(), connection.clone());
                
                counter!("rustwaf.tunnel.waf_peers.connected").increment(1);
                tracing::info!("Connected to WAF peer: {}", name);
                
                Ok(connection)
            }
            PeerMessage::AuthFailure { reason } => {
                tracing::error!("Failed to connect to peer {}: {}", name, reason);
                Err(format!("Peer authentication failed: {}", reason).into())
            }
            _ => Err("Unexpected response from peer".into())
        }
    }

    pub async fn get_peer(&self, name: &str) -> Option<PeerConnection> {
        self.peers.get(name).map(|p| p.clone())
    }

    pub async fn list_peers(&self) -> Vec<PeerConnection> {
        self.peers.iter().map(|p| p.clone()).collect()
    }

    pub fn shutdown(&self) {
        let _ = self.shutdown_tx.send(());
    }

    fn ip_matches_peer(peer_address: &str, remote_ip: std::net::IpAddr) -> bool {
        if let Ok(addr) = peer_address.parse::<std::net::SocketAddr>() {
            return addr.ip() == remote_ip;
        }
        
        if let Ok(ip) = peer_address.parse::<std::net::IpAddr>() {
            return ip == remote_ip;
        }
        
        false
    }
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub enum PeerMessage {
    Hello {
        peer_id: String,
        auth_token: String,
    },
    HelloAck {
        session_id: String,
    },
    AuthFailure {
        reason: String,
    },
    Request {
        path: String,
        method: String,
        headers: HashMap<String, String>,
    },
    Response {
        status: u16,
        body: Vec<u8>,
    },
    HealthCheck,
    HealthCheckAck,
}
