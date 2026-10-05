use std::net::SocketAddr;
use std::sync::Arc;

use parking_lot::RwLock;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio_rustls::TlsAcceptor;

use crate::secure_transport::SecureTransportConfig;
use crate::server::DnsServer;

pub const TLS_HANDSHAKE_TIMEOUT_SECS: u64 = 10;
pub const MAX_QUERY_SIZE: usize = 65535;

/// Transport configuration consumed by the encrypted-DNS listeners.
///
/// Phase 126: implementations are DNS-owned runtime types, not persisted
/// schema types. The bind socket is already parsed and validated at
/// conversion time, so `bind_address` returns a typed `SocketAddr`.
pub trait DnsServerConfig: Send + Sync + Clone + 'static {
    /// Parsed listener socket, or `None` when the transport is disabled.
    fn bind_address(&self) -> Option<SocketAddr>;
    fn server_name(&self) -> &'static str;
}

pub struct SecureDnsServerBase<C: DnsServerConfig> {
    pub config: Arc<C>,
    pub cert_resolver: Option<Arc<dyn SecureTransportConfig>>,
    pub dns_server: Arc<RwLock<Option<DnsServer>>>,
    pub shutdown_tx: Option<oneshot::Sender<()>>,
}

impl<C: DnsServerConfig> SecureDnsServerBase<C> {
    pub fn new(config: C, cert_resolver: Option<Arc<dyn SecureTransportConfig>>) -> Self {
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

    /// Build the stream-transport acceptor (DoT, DoH).
    ///
    /// The two literals here are duplicated in `doq.rs::create_tls_config`,
    /// which cannot share this base because QUIC needs a
    /// `QuicServerConfig` rather than a `TlsAcceptor`. Keep the two in step;
    /// the guard
    /// `encrypted_transport_error_contract_is_duplicated_consistently` fails if
    /// they drift.
    pub fn create_tls_acceptor(&self) -> Result<TlsAcceptor, String> {
        self.cert_resolver
            .as_ref()
            .ok_or_else(|| "No TLS certificate resolver available".to_string())
            .and_then(|provider| {
                provider
                    .server_config()
                    .map(TlsAcceptor::from)
                    .map_err(|e| format!("Failed to build TLS config: {}", e))
            })
    }

    pub async fn start_server<F, Fut>(
        &mut self,
        bind_address: SocketAddr,
        server_name: &'static str,
        handle_connection: F,
    ) -> Result<(), String>
    where
        F: Fn(
                tokio::net::TcpStream,
                SocketAddr,
                Arc<RwLock<Option<DnsServer>>>,
                Arc<TlsAcceptor>,
            ) -> Fut
            + Send
            + Sync
            + Clone
            + 'static,
        Fut: std::future::Future<Output = Result<(), String>> + Send,
    {
        if bind_address.port() == 0 {
            return Err(format!(
                "Invalid {} bind address: port cannot be zero",
                server_name
            ));
        }

        let bind_addr = bind_address;

        let listener = TcpListener::bind(bind_addr)
            .await
            .map_err(|e| format!("Failed to bind {} socket: {}", server_name, e))?;

        tracing::info!("{} server listening on {}", server_name, bind_addr);

        let acceptor = Arc::new(self.create_tls_acceptor()?);

        let dns_server = self.dns_server.clone();
        let config = self.config.clone();

        let (tx, rx) = oneshot::channel::<()>();
        self.shutdown_tx = Some(tx);

        tokio::spawn(async move {
            Self::accept_loop(
                listener,
                dns_server,
                config,
                acceptor,
                rx,
                handle_connection,
            )
            .await;
        });

        Ok(())
    }

    async fn accept_loop<F, Fut>(
        listener: TcpListener,
        dns_server: Arc<RwLock<Option<DnsServer>>>,
        _config: Arc<C>,
        acceptor: Arc<TlsAcceptor>,
        shutdown_rx: oneshot::Receiver<()>,
        handle_connection: F,
    ) where
        F: Fn(
                tokio::net::TcpStream,
                SocketAddr,
                Arc<RwLock<Option<DnsServer>>>,
                Arc<TlsAcceptor>,
            ) -> Fut
            + Send
            + Sync
            + Clone
            + 'static,
        Fut: std::future::Future<Output = Result<(), String>> + Send,
    {
        tokio::select! {
            _ = shutdown_rx => {
                tracing::info!("DNS server shutting down");
            }
            _ = async {
                loop {
                    match listener.accept().await {
                        Ok((stream, client_addr)) => {
                            let dns_server = dns_server.clone();
                            let acceptor = acceptor.clone();
                            let handler = handle_connection.clone();

                            tokio::spawn(async move {
                                if let Err(e) = handler(stream, client_addr, dns_server, acceptor).await {
                                    tracing::debug!("Connection error from {}: {}", client_addr, e);
                                }
                            });
                        }
                        Err(e) => {
                            tracing::error!("Accept error: {}", e);
                        }
                    }
                }
            } => {}
        }
    }

    pub fn shutdown(&mut self) {
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(());
        }
    }
}

impl<C: DnsServerConfig> Clone for SecureDnsServerBase<C> {
    fn clone(&self) -> Self {
        Self {
            config: self.config.clone(),
            cert_resolver: self.cert_resolver.clone(),
            dns_server: self.dns_server.clone(),
            shutdown_tx: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone)]
    struct TestConfig;

    impl DnsServerConfig for TestConfig {
        fn bind_address(&self) -> Option<SocketAddr> {
            Some(SocketAddr::from(([127, 0, 0, 1], 0)))
        }

        fn server_name(&self) -> &'static str {
            "Test"
        }
    }

    async fn dummy_handler(
        _stream: tokio::net::TcpStream,
        _addr: SocketAddr,
        _dns: Arc<RwLock<Option<DnsServer>>>,
        _acceptor: Arc<TlsAcceptor>,
    ) -> Result<(), String> {
        Ok(())
    }

    /// Phase 45 Workstream C: an occupied port must surface as a bind error
    /// (not a hang or silent fallback), matching UDP/TCP fail-fast behavior.
    /// Binding happens before TLS acceptor creation, so no certificates are
    /// needed to exercise this path.
    #[tokio::test]
    async fn bind_collision_is_surfaced() {
        let occupied = std::net::TcpListener::bind("127.0.0.1:0").expect("occupy port");
        let port = occupied.local_addr().expect("local addr").port();

        let mut base = SecureDnsServerBase::new(TestConfig, None);
        let err = base
            .start_server(
                SocketAddr::from(([127, 0, 0, 1], port)),
                "Test server",
                dummy_handler,
            )
            .await
            .expect_err("bind collision must fail");
        assert!(
            err.contains("Failed to bind"),
            "error must mention bind failure, got: {}",
            err
        );
    }

    /// A zero port fails before any socket is created. An unparseable address
    /// no longer reaches this layer — the application adapter rejects it with
    /// a typed conversion error before any server is constructed.
    #[tokio::test]
    async fn zero_port_bind_fails_fast() {
        let mut base = SecureDnsServerBase::new(TestConfig, None);
        let err = base
            .start_server(
                SocketAddr::from(([127, 0, 0, 1], 0)),
                "Test server",
                dummy_handler,
            )
            .await
            .expect_err("zero port must fail");
        assert!(
            err.contains("Invalid Test server bind address"),
            "got: {}",
            err
        );
    }
}
