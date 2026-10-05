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

/// ALPN protocol identifiers a stream transport advertises, in preference
/// order.
///
/// This is a **parameter** and not a constant here because DoT and DoH share
/// this base and RFC-correct for only one of them. Phase 137:
///
/// - DoT advertises nothing. RFC 7858 defines no ALPN identifier for
///   DNS-over-TLS, and mainstream DoT clients offer none. `dot` is
///   IANA-registered, but advertising it would make rustls *require* a
///   negotiated match and reject exactly those clients.
/// - DoH advertises `h2`, because its handler is HTTP/2-only by construction.
///
/// Each transport declares its own value next to its protocol implementation
/// (`dot::DOT_ALPN`, `doh::DOH_ALPN`). Nothing reads ALPN from the runtime
/// configuration, because a served protocol constant is absent by design
/// (`runtime_config.rs`, and the F-2 `PERSISTENCE` precedent in
/// `architecture/dns_config_runtime_matrix.md`) — a knob here would recreate
/// the inert-setting problem this campaign exists to close.
pub type AlpnProtocols = &'static [&'static [u8]];

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

/// Attach ALPN to a provider-supplied server configuration.
///
/// The provider returns an `Arc<ServerConfig>` shared behind its own `Arc`, and
/// `rustls::ServerConfig` is `Clone`. That clone is **shallow**: the
/// certificate resolver is itself `Arc`-backed, so a clone keeps certificate
/// reload visible through the already-built config — the property
/// `a_reload_is_visible_through_an_already_built_server_config` pins in
/// `crates/synvoid-tls/tests/cert_resolver_provider_evidence.rs`. A
/// configuration that is not ALPN-relevant is returned untouched, with no
/// clone at all, so DoT's config is the provider's own object.
///
/// `doq.rs` performs the equivalent mutation for its `QuicServerConfig` and is
/// deliberately not routed through here.
fn with_alpn(
    shared: Arc<rustls::ServerConfig>,
    alpn_protocols: &[&[u8]],
) -> Arc<rustls::ServerConfig> {
    if alpn_protocols.is_empty() {
        return shared;
    }
    let mut config = (*shared).clone();
    config.alpn_protocols = alpn_protocols.iter().map(|p| p.to_vec()).collect();
    Arc::new(config)
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
    ///
    /// `alpn_protocols` is supplied by the caller rather than read from the
    /// provider: see [`AlpnProtocols`]. The provider deliberately configures no
    /// ALPN (Phase 134), because it must not decide which DNS protocol its
    /// listener speaks.
    pub fn create_tls_acceptor(&self, alpn_protocols: &[&[u8]]) -> Result<TlsAcceptor, String> {
        self.cert_resolver
            .as_ref()
            .ok_or_else(|| "No TLS certificate resolver available".to_string())
            .and_then(|provider| {
                provider
                    .server_config()
                    .map(|shared| TlsAcceptor::from(with_alpn(shared, alpn_protocols)))
                    .map_err(|e| format!("Failed to build TLS config: {}", e))
            })
    }

    pub async fn start_server<F, Fut>(
        &mut self,
        bind_address: SocketAddr,
        server_name: &'static str,
        alpn_protocols: &[&[u8]],
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

        let acceptor = Arc::new(self.create_tls_acceptor(alpn_protocols)?);

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
                &[],
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
                &[],
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
