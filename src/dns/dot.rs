use std::net::SocketAddr;
use std::sync::Arc;

use parking_lot::RwLock;
use tokio::net::TcpListener;
use tokio::net::TcpStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::sync::oneshot;
use tokio_rustls::TlsAcceptor;
use bytes::Buf;

use crate::config::dns::DnsDotConfig;
use crate::dns::server::{DnsServer, RecordType};
use crate::dns::cache::CacheKey;
use crate::tls::cert_resolver::CertResolver;

const DOT_MAX_QUERY_SIZE: usize = 65535;
const DOT_TLS_HANDSHAKE_TIMEOUT_SECS: u64 = 10;

pub struct DotServer {
    config: Arc<DnsDotConfig>,
    cert_resolver: Option<Arc<CertResolver>>,
    dns_server: Arc<RwLock<Option<DnsServer>>>,
    shutdown_tx: Option<oneshot::Sender<()>>,
}

impl DotServer {
    pub fn new(config: DnsDotConfig, cert_resolver: Option<Arc<CertResolver>>) -> Self {
        Self {
            config: Arc::new(config),
            cert_resolver,
            dns_server: Arc::new(RwLock::new(None)),
            shutdown_tx: None,
        }
    }

    pub fn set_dns_server(&self, server: DnsServer) {
        *self.dns_server.write() = Some(server);
    }

    pub async fn start(&mut self) -> Result<(), String> {
        let bind_addr = format!("{}:{}", self.config.bind_address, self.config.port)
            .parse::<SocketAddr>()
            .map_err(|e| format!("Invalid DoT bind address: {}", e))?;

        let listener = TcpListener::bind(bind_addr)
            .await
            .map_err(|e| format!("Failed to bind DoT socket: {}", e))?;

        tracing::info!("DoT server listening on {}", bind_addr);

        let acceptor = self.create_tls_acceptor()?;

        let dns_server = self.dns_server.clone();
        let config = self.config.clone();

        let (tx, rx) = oneshot::channel::<()>();
        self.shutdown_tx = Some(tx);

        tokio::spawn(async move {
            Self::accept_loop(listener, dns_server, config, acceptor, rx).await;
        });

        Ok(())
    }

    fn create_tls_acceptor(&self) -> Result<TlsAcceptor, String> {
        if let Some(ref resolver) = self.cert_resolver {
            let server_config = resolver.build_server_config()
                .map_err(|e| format!("Failed to build TLS config: {}", e))?;
            Ok(TlsAcceptor::from(server_config))
        } else {
            Err("No TLS certificate resolver available".to_string())
        }
    }

    async fn accept_loop(
        listener: TcpListener,
        dns_server: Arc<RwLock<Option<DnsServer>>>,
        config: Arc<DnsDotConfig>,
        acceptor: TlsAcceptor,
        shutdown_rx: oneshot::Receiver<()>,
    ) {
        tokio::select! {
            _ = shutdown_rx => {
                tracing::info!("DoT server shutting down");
            }
            _ = async {
                let acceptor = acceptor;
                loop {
                    match listener.accept().await {
                        Ok((stream, client_addr)) => {
                            let dns_server = dns_server.clone();
                            let acceptor = acceptor.clone();

                            tokio::spawn(async move {
                                if let Err(e) = Self::handle_connection(stream, client_addr, dns_server, acceptor).await {
                                    tracing::debug!("DoT connection error from {}: {}", client_addr, e);
                                }
                            });
                        }
                        Err(e) => {
                            tracing::error!("DoT accept error: {}", e);
                        }
                    }
                }
            } => {}
        }
    }

    async fn handle_connection(
        stream: TcpStream,
        client_addr: SocketAddr,
        dns_server: Arc<RwLock<Option<DnsServer>>>,
        acceptor: TlsAcceptor,
    ) -> Result<(), String> {
        use std::time::Duration;

        let tls_stream = tokio::time::timeout(
            Duration::from_secs(DOT_TLS_HANDSHAKE_TIMEOUT_SECS),
            acceptor.accept(stream),
        )
        .await
        .map_err(|_| "TLS handshake timeout")?
        .map_err(|e| format!("TLS handshake failed: {}", e))?;

        let mut tls_stream = tls_stream;

        loop {
            let client_ip = client_addr.ip();

            let mut length_buf = [0u8; 2];
            match tls_stream.read_exact(&mut length_buf).await {
                Ok(_) => {}
                Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                    return Ok(());
                }
                Err(e) => {
                    return Err(format!("Failed to read length prefix: {}", e));
                }
            };

            let length = u16::from_be_bytes(length_buf) as usize;

            if length > DOT_MAX_QUERY_SIZE || length == 0 {
                return Err(format!("Invalid query length: {}", length));
            }

            let mut query_buf = vec![0u8; length];
            tls_stream.read_exact(&mut query_buf).await
                .map_err(|e| format!("Failed to read query: {}", e))?;

            let (zones, zone_trie, zone_index, cache, dnssec, signer_name, ecs_config) = {
                let dns_server_guard = dns_server.read();
                let server = match dns_server_guard.as_ref() {
                    Some(s) => s,
                    None => {
                        return Err("DNS server not configured".to_string());
                    }
                };

                (
                    server.get_zones(),
                    server.get_zone_trie(),
                    server.get_zone_index(),
                    server.get_cache(),
                    server.get_dnssec(),
                    server.get_signer_name(),
                    server.get_ecs_filter_config(),
                )
            };

            let response = if let Some(ref c) = cache {
                let cache_key = CacheKey::new(String::new(), RecordType::NULL, Some(client_ip));
                DnsServer::handle_query_with_cache(
                    &zones,
                    &zone_trie,
                    &query_buf,
                    None,
                    None,
                    60,
                    c,
                    cache_key,
                    dnssec.as_ref(),
                    signer_name.as_ref(),
                    Some(client_ip),
                    None,
                    &ecs_config,
                    None,
                    None,
                )
            } else {
                DnsServer::handle_query(
                    &zones,
                    &zone_trie,
                    &query_buf,
                    None,
                    None,
                    60,
                    Some(client_ip),
                    &ecs_config,
                    None,
                    None,
                )
            };

            match response {
                Some(resp) => {
                    let response_len = resp.len() as u16;
                    tls_stream.write_all(&response_len.to_be_bytes()).await
                        .map_err(|e| format!("Failed to send response length: {}", e))?;
                    tls_stream.write_all(&resp).await
                        .map_err(|e| format!("Failed to send response: {}", e))?;
                }
                None => {
                    let empty_response: Vec<u8> = vec![0; 2];
                    tls_stream.write_all(&empty_response).await
                        .map_err(|e| format!("Failed to send empty response: {}", e))?;
                }
            }
        }
    }

    pub fn shutdown(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

impl Clone for DotServer {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            cert_resolver: self.cert_resolver.clone(),
            dns_server: self.dns_server.clone(),
            shutdown_tx: None,
        }
    }
}
