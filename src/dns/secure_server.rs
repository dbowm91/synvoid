use std::net::SocketAddr;
use std::sync::Arc;

use parking_lot::RwLock;
use tokio::net::TcpListener;
use tokio::sync::oneshot;
use tokio_rustls::TlsAcceptor;

use crate::dns::server::DnsServer;
use crate::tls::cert_resolver::CertResolver;

pub const TLS_HANDSHAKE_TIMEOUT_SECS: u64 = 10;
pub const MAX_QUERY_SIZE: usize = 65535;

pub trait DnsServerConfig: Send + Sync + Clone + 'static {
    fn bind_address(&self) -> &str;
    fn port(&self) -> u16;
    fn server_name(&self) -> &'static str;
}

pub struct SecureDnsServerBase<C: DnsServerConfig> {
    pub config: Arc<C>,
    pub cert_resolver: Option<Arc<CertResolver>>,
    pub dns_server: Arc<RwLock<Option<DnsServer>>>,
    pub shutdown_tx: Option<oneshot::Sender<()>>,
}

impl<C: DnsServerConfig> SecureDnsServerBase<C> {
    pub fn new(config: C, cert_resolver: Option<Arc<CertResolver>>) -> Self {
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

    pub fn create_tls_acceptor(&self) -> Result<TlsAcceptor, String> {
        self.cert_resolver
            .as_ref()
            .ok_or_else(|| "No TLS certificate resolver available".to_string())
            .and_then(|resolver| {
                resolver
                    .build_server_config()
                    .map(TlsAcceptor::from)
                    .map_err(|e| format!("Failed to build TLS config: {}", e))
            })
    }

    pub async fn start_server<F, Fut>(
        &mut self,
        bind_address: &str,
        port: u16,
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
        let bind_addr = format!("{}:{}", bind_address, port)
            .parse::<SocketAddr>()
            .map_err(|e| format!("Invalid {} bind address: {}", server_name, e))?;

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
