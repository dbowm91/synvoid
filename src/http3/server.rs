use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::broadcast;

use metrics::{counter, gauge};

use crate::waf::WafCore;
use crate::worker::drain_state::WorkerDrainState;
use synvoid_config::http::Http3Config;
use synvoid_config::MainConfig;
use synvoid_http_client::{create_http_client_with_config, HttpClient};
use synvoid_metrics::bandwidth::get_global_bandwidth_tracker_or_log;
use synvoid_metrics::WorkerMetrics;
use synvoid_proxy::Router;
use synvoid_proxy::UpstreamClientRegistry;
use synvoid_waf::access::WafAccess;
use synvoid_waf::{FloodDecision, FloodProtector};

pub struct Http3Server {
    addr: SocketAddr,
    config: Http3Config,
    router: Arc<Router>,
    waf: Arc<WafCore>,
    flood_protector: Option<Arc<FloodProtector>>,
    client: HttpClient,
    upstream_client_registry: Arc<UpstreamClientRegistry>,
    drain_state: Option<Arc<WorkerDrainState>>,
    metrics: Option<Arc<WorkerMetrics>>,
    shutdown_rx: broadcast::Receiver<()>,
    trusted_proxies: Vec<String>,
    main_config: Arc<MainConfig>,
}

impl Http3Server {
    pub fn new(
        addr: SocketAddr,
        config: Http3Config,
        router: Router,
        waf: Arc<WafCore>,
        main_config: MainConfig,
        shutdown_rx: broadcast::Receiver<()>,
    ) -> Self {
        let client =
            create_http_client_with_config(Duration::from_secs(5), 100, Duration::from_secs(30));

        let trusted_proxies = main_config.server.trusted_proxies.clone();

        Self {
            addr,
            config,
            router: Arc::new(router),
            waf,
            flood_protector: None,
            client,
            upstream_client_registry: Arc::new(UpstreamClientRegistry::new()),
            drain_state: None,
            metrics: None,
            shutdown_rx,
            trusted_proxies,
            main_config: Arc::new(main_config),
        }
    }

    pub fn with_flood_protector(mut self, flood_protector: Arc<FloodProtector>) -> Self {
        self.flood_protector = Some(flood_protector);
        self
    }

    pub fn with_drain_state(mut self, drain_state: Arc<WorkerDrainState>) -> Self {
        self.drain_state = Some(drain_state);
        self
    }

    pub fn with_metrics(mut self, metrics: Arc<WorkerMetrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    pub async fn serve(
        self,
        tls_config: Arc<rustls::ServerConfig>,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        if !self.config.enabled {
            return Ok(());
        }

        // Fix for quinn 0.11: use QuicServerConfig::try_from
        let quic_server_config = quinn::crypto::rustls::QuicServerConfig::try_from(tls_config)
            .map_err(|e| format!("Failed to create QUIC server config: {}", e))?;

        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(quic_server_config));

        let transport_config =
            Arc::get_mut(&mut server_config.transport).expect("Failed to get transport config");
        transport_config.max_concurrent_uni_streams(0_u8.into());
        transport_config.max_concurrent_bidi_streams(100_u32.into());

        let idle_timeout = quinn::IdleTimeout::try_from(std::time::Duration::from_secs(60))
            .expect("Failed to create idle timeout");
        transport_config.max_idle_timeout(Some(idle_timeout));

        let std_socket = crate::platform::socket::bind_udp_reuse(self.addr)?;
        let endpoint = quinn::Endpoint::new(
            quinn::EndpointConfig::default(),
            Some(server_config),
            std_socket,
            Arc::new(quinn::TokioRuntime),
        )
        .map_err(|e| format!("Failed to create QUIC endpoint: {}", e))?;

        tracing::info!("HTTP/3 server listening on {} [SO_REUSEPORT]", self.addr);

        let self_arc = Arc::new(self);
        let mut shutdown_rx = self_arc.shutdown_rx.resubscribe();

        loop {
            tokio::select! {
                incoming = endpoint.accept() => {
                    match incoming {
                        Some(conn) => {
                            let s = self_arc.clone();
                            tokio::spawn(async move {
                                if let Err(e) = s.handle_quic_connection(conn).await {
                                    tracing::debug!("HTTP/3 connection error: {}", e);
                                }
                            });
                        }
                        None => {
                            tracing::info!("HTTP/3 endpoint closed");
                            break;
                        }
                    }
                }
                _ = shutdown_rx.recv() => {
                    tracing::info!("HTTP/3 server received shutdown signal");
                    endpoint.close(0u32.into(), b"Server shutdown");
                    break;
                }
            }
        }

        tracing::info!("HTTP/3 server shutdown complete");
        Ok(())
    }

    async fn handle_quic_connection(
        self: Arc<Self>,
        incoming: quinn::Incoming,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let connection = incoming.await.map_err(|e| {
            counter!("synvoid.http3.connection.errors").increment(1);
            format!("Connection failed: {}", e)
        })?;

        let remote_addr = connection.remote_address();
        let client_ip = remote_addr.ip();

        tracing::debug!("HTTP/3 connection from {}", remote_addr);

        if let Some(ref fp) = self.flood_protector {
            match fp.check_tcp_connection(client_ip) {
                FloodDecision::Blackholed => {
                    counter!("synvoid.http3.flood_blackhole").increment(1);
                    return Ok(());
                }
                FloodDecision::RateLimited => {
                    counter!("synvoid.http3.flood_limited").increment(1);
                    return Ok(());
                }
                FloodDecision::Allowed => {}
            }
        }

        gauge!("synvoid.http3.connections").increment(1.0);
        counter!("synvoid.http3.connections.total").increment(1);

        let server_builder = h3::server::builder();
        let mut h3_conn = server_builder
            .build(h3_quinn::Connection::new(connection))
            .await
            .map_err(|e| {
                counter!("synvoid.http3.connection.errors").increment(1);
                format!("Failed to create H3 connection: {}", e)
            })?;

        loop {
            match h3_conn.accept().await {
                Ok(Some(resolver)) => {
                    let s = self.clone();
                    tokio::spawn(async move {
                        if let Err(e) = s.handle_request(resolver, remote_addr).await {
                            tracing::debug!("HTTP/3 request error: {}", e);
                        }
                    });
                }
                Ok(None) => {
                    tracing::debug!("HTTP/3 connection closed by peer");
                    break;
                }
                Err(e) => {
                    tracing::debug!("HTTP/3 accept error: {}", e);
                    counter!("synvoid.http3.connection.errors").increment(1);
                    break;
                }
            }
        }

        gauge!("synvoid.http3.connections").decrement(1.0);
        Ok(())
    }

    async fn handle_request(
        self: Arc<Self>,
        resolver: h3::server::RequestResolver<h3_quinn::Connection, bytes::Bytes>,
        remote_addr: SocketAddr,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        let start = Instant::now();
        let max_request_size = self.config.max_request_size;
        let flow = match synvoid_http::prepare_http3_request_dispatch(
            start,
            resolver,
            remote_addr,
            &self.trusted_proxies,
            &self.router,
            self.waf.connection_limiter().as_ref(),
            self.waf.is_over_bandwidth_limit(),
        )
        .await
        {
            Ok(synvoid_http::Http3RequestDispatchOutcome::Continue(flow)) => flow,
            Ok(synvoid_http::Http3RequestDispatchOutcome::Respond) => {
                return Ok(());
            }
            Err(e) => return Err(Box::new(e)),
        };

        let synvoid_http::Http3RequestDispatchContext {
            prelude,
            mut request_stream,
            connection_guard,
        } = flow;
        let synvoid_http::Http3RequestPrelude {
            parts,
            route_result,
            client_ip,
            path,
            host,
            query_string,
            user_agent,
        } = prelude;
        let method = parts.method.clone();

        tracing::trace!("HTTP/3 {} {} from {}", method, parts.uri, remote_addr);

        let bandwidth = get_global_bandwidth_tracker_or_log();
        synvoid_http::handle_http3_request_dispatch(
            start,
            &route_result,
            &path,
            &method,
            &parts.headers,
            &host,
            query_string.as_deref(),
            user_agent.as_deref(),
            client_ip,
            &mut request_stream,
            max_request_size,
            self.waf.streaming(),
            self.waf.streaming(),
            connection_guard.as_ref(),
            self.waf.connection_limiter().as_ref(),
            &self.main_config,
            &self.client,
            &self.upstream_client_registry,
            bandwidth.as_ref(),
            self.metrics.as_ref(),
            self.waf.as_ref(),
        )
        .await?;

        Ok(())
    }

    pub fn alt_svc_header(&self) -> String {
        if self.config.enabled {
            format!(
                "h3=\":{}\"; ma={}",
                self.config.port, self.config.alt_svc_max_age
            )
        } else {
            String::new()
        }
    }
}
