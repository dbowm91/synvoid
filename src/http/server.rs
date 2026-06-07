#![allow(
    clippy::type_complexity,
    clippy::collapsible_match,
    clippy::manual_div_ceil,
    clippy::unnecessary_to_owned,
    clippy::field_reassign_with_default,
    clippy::collapsible_if
)]

use bytes::Bytes;
use http::Response;
use http_body_util::combinators::BoxBody;
use metrics::counter;
use std::collections::HashMap;
use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::sync::broadcast;
use tokio::sync::Semaphore;

use crate::http_client::ErasedHttpClient;
use synvoid_http::RequestPreparationOutcome;

mod accept_loop;
mod connection_types;
mod observability;

pub(crate) use observability::send_request_log_if_enabled;

use connection_types::*;

use crate::config::HttpConfig;
use crate::config::MainConfig;

#[allow(unused_imports)]
use crate::http_client::{create_http_client_with_config, HttpClient};
#[cfg(feature = "mesh")]
use crate::mesh::config::MeshConfig;
#[cfg(feature = "mesh")]
use crate::mesh::transports::MeshTransportManager;
#[cfg(feature = "mesh")]
use crate::mesh::MeshBackendPool;
use crate::metrics::WorkerMetrics;
use crate::router::Router;
use crate::waf::{FloodDecision, FloodProtector, WafCore};
use crate::worker::drain_state::WorkerDrainState;
use synvoid_proxy::UpstreamClientRegistry;
use tokio::sync::RwLock;

pub struct HttpServer {
    addr: SocketAddr,
    router: Arc<Router>,
    waf: Arc<WafCore>,
    flood_protector: Option<Arc<FloodProtector>>,
    client: HttpClient,
    shutdown_rx: broadcast::Receiver<()>,
    http_config: HttpConfig,
    alt_svc: Option<String>,
    main_config: Arc<MainConfig>,
    drain_state: Option<Arc<WorkerDrainState>>,
    #[cfg(feature = "mesh")]
    mesh_config: Option<Arc<MeshConfig>>,
    #[cfg(feature = "mesh")]
    mesh_transport: Option<Arc<MeshTransportManager>>,
    metrics: Option<Arc<WorkerMetrics>>,
    ipc: Option<Arc<tokio::sync::Mutex<crate::process::ipc_transport::IpcStream>>>,
    worker_id: Option<crate::process::ipc::WorkerId>,
    serverless_manager: Option<Arc<crate::serverless::manager::ServerlessManager>>,
    connection_limit: Arc<Semaphore>,
    app_servers: Option<Arc<RwLock<HashMap<String, Arc<crate::app_server::GranianSupervisor>>>>>,
    #[cfg(feature = "mesh")]
    mesh_backend_pool: Option<Arc<MeshBackendPool>>,
    upstream_client_registry: Arc<UpstreamClientRegistry>,
    erased_http_client: ErasedHttpClient,
}

impl HttpServer {
    pub fn new(
        addr: SocketAddr,
        router: Router,
        waf: Arc<WafCore>,
        http_config: HttpConfig,
        shutdown_rx: broadcast::Receiver<()>,
        main_config: MainConfig,
    ) -> Self {
        let client = create_http_client_with_config(
            std::time::Duration::from_secs(5),
            100,
            std::time::Duration::from_secs(30),
        );

        let max_connections = http_config.max_connections as usize;

        Self {
            addr,
            router: Arc::new(router),
            waf,
            flood_protector: None,
            client,
            shutdown_rx,
            http_config,
            alt_svc: None,
            main_config: Arc::new(main_config),
            drain_state: None,
            #[cfg(feature = "mesh")]
            mesh_config: None,
            #[cfg(feature = "mesh")]
            mesh_transport: None,
            metrics: None,
            ipc: None,
            worker_id: None,
            serverless_manager: None,
            connection_limit: Arc::new(Semaphore::new(max_connections)),
            app_servers: None,
            #[cfg(feature = "mesh")]
            mesh_backend_pool: None,
            upstream_client_registry: Arc::new(UpstreamClientRegistry::new()),
            erased_http_client: ErasedHttpClient::new(100),
        }
    }

    pub fn with_serverless_manager(
        mut self,
        manager: Arc<crate::serverless::manager::ServerlessManager>,
    ) -> Self {
        self.serverless_manager = Some(manager);
        self
    }

    pub fn with_metrics(mut self, metrics: Arc<WorkerMetrics>) -> Self {
        self.metrics = Some(metrics);
        self
    }

    pub fn with_ipc(
        mut self,
        ipc: Arc<tokio::sync::Mutex<crate::process::ipc_transport::IpcStream>>,
        worker_id: crate::process::ipc::WorkerId,
    ) -> Self {
        self.ipc = Some(ipc);
        self.worker_id = Some(worker_id);
        self
    }

    pub fn with_flood_protector(mut self, flood_protector: Arc<FloodProtector>) -> Self {
        self.flood_protector = Some(flood_protector);
        self
    }

    pub fn with_alt_svc(mut self, alt_svc: String) -> Self {
        self.alt_svc = Some(alt_svc);
        self
    }

    pub fn with_drain_state(mut self, drain_state: Arc<WorkerDrainState>) -> Self {
        self.drain_state = Some(drain_state);
        self
    }

    #[cfg(feature = "mesh")]
    pub fn with_mesh_config(mut self, mesh_config: Option<Arc<MeshConfig>>) -> Self {
        self.mesh_config = mesh_config;
        self
    }

    #[cfg(feature = "mesh")]
    pub fn with_mesh_transport(mut self, transport: Option<Arc<MeshTransportManager>>) -> Self {
        self.mesh_transport = transport;
        self
    }

    pub fn with_app_servers(
        mut self,
        app_servers: Option<
            Arc<RwLock<HashMap<String, Arc<crate::app_server::GranianSupervisor>>>>,
        >,
    ) -> Self {
        self.app_servers = app_servers;
        self
    }

    #[cfg(feature = "mesh")]
    pub fn with_mesh_backend_pool(mut self, pool: Option<Arc<MeshBackendPool>>) -> Self {
        self.mesh_backend_pool = pool;
        self
    }

    #[cfg(feature = "mesh")]
    pub async fn serve(self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        accept_loop::run_accept_loop(
            self.addr,
            self.shutdown_rx,
            self.router,
            self.waf,
            self.client,
            self.flood_protector,
            self.http_config,
            self.alt_svc,
            self.main_config,
            self.drain_state,
            #[cfg(feature = "mesh")]
            self.mesh_config,
            #[cfg(feature = "mesh")]
            self.mesh_transport,
            self.metrics,
            self.ipc,
            self.worker_id,
            self.serverless_manager,
            self.connection_limit,
            self.app_servers,
            #[cfg(feature = "mesh")]
            self.mesh_backend_pool,
            self.upstream_client_registry,
            self.erased_http_client,
        )
        .await
    }

    #[allow(unused_assignments)]
    async fn handle_request(
        req: hyper::Request<hyper::body::Incoming>,
        client_addr: SocketAddr,
        local_addr: Option<SocketAddr>,
        router: Arc<Router>,
        waf: Arc<WafCore>,
        client: HttpClient,
        alt_svc: Option<String>,
        main_config: Arc<MainConfig>,
        drain_state: Option<Arc<WorkerDrainState>>,
        http_config: HttpConfig,
        #[cfg(feature = "mesh")] mesh_config: Option<Arc<MeshConfig>>,
        #[cfg(feature = "mesh")] mesh_transport: Option<Arc<MeshTransportManager>>,
        metrics: Option<Arc<WorkerMetrics>>,
        http_conn: Arc<HttpConnection>,
        ipc: Option<Arc<tokio::sync::Mutex<crate::process::ipc_transport::IpcStream>>>,
        worker_id: Option<crate::process::ipc::WorkerId>,
        serverless_manager: Option<Arc<crate::serverless::manager::ServerlessManager>>,
        connection_limit: Arc<Semaphore>,
        app_servers: Option<
            Arc<RwLock<HashMap<String, Arc<crate::app_server::GranianSupervisor>>>>,
        >,
        #[cfg(feature = "mesh")] mesh_backend_pool: Option<Arc<MeshBackendPool>>,
        upstream_client_registry: Arc<UpstreamClientRegistry>,
        _erased_http_client: ErasedHttpClient,
    ) -> Result<Response<BoxBody<Bytes, Infallible>>, hyper::Error> {
        let request_queue_started_at = Instant::now();
        let _permit = match connection_limit.clone().acquire_owned().await {
            Ok(p) => p,
            Err(_) => {
                tracing::error!("Connection limit semaphore closed");
                return Ok(synvoid_http::response_builder::build_response_with_alt_svc(
                    503,
                    "Service Unavailable".to_string(),
                    "text/plain",
                    &alt_svc,
                    &main_config,
                ));
            }
        };
        let request_queue_time_ms = request_queue_started_at.elapsed().as_millis() as u64;
        if let Some(metrics) = &metrics {
            metrics.record_request_queue_time_ms(request_queue_time_ms);
        }

        let start = std::time::Instant::now();
        let request_drop: Arc<dyn Fn() + Send + Sync> = {
            let http_conn = http_conn.clone();
            Arc::new(move || http_conn.request_drop())
        };
        let flow = synvoid_http::prepare_http_request_flow(
            req,
            client_addr.ip(),
            local_addr,
            &drain_state,
            &router,
            &waf,
            &alt_svc,
            &main_config,
            &http_config,
            &metrics,
            ipc.clone(),
            worker_id,
            start,
            Arc::clone(&request_drop),
            send_request_log_if_enabled,
            #[cfg(feature = "mesh")]
            &mesh_config,
            #[cfg(feature = "mesh")]
            &mesh_transport,
            #[cfg(feature = "mesh")]
            &serverless_manager,
            &upstream_client_registry,
        )
        .await?;

        let client_ip = flow.client_ip;
        let prepared = match flow.outcome {
            RequestPreparationOutcome::Continue(prepared) => prepared,
            RequestPreparationOutcome::Respond(response) => {
                return Ok(response);
            }
        };

        let _drain_guard = DrainGuard::new(drain_state);
        let plugin_backend = router
            .plugin_manager()
            .and_then(|pm| pm.downcast_ref::<crate::plugin::PluginManager>())
            .map(|pm| pm as &dyn synvoid_http::WasmFilterBackend);
        let axum_router_lookup = router
            .plugin_manager()
            .and_then(|pm| pm.downcast_ref::<crate::plugin::PluginManager>())
            .map(|pm| pm as &dyn synvoid_http::AxumDynamicRouterLookup);

        synvoid_http::handle_http_request_postlude(
            synvoid_http::HttpRequestPostludeContext {
                prepared,
                client_ip,
                router: &router,
                waf: &waf,
                client: &client,
                alt_svc: &alt_svc,
                main_config: &main_config,
                http_config: &http_config,
                metrics: &metrics,
                ipc: ipc.clone(),
                worker_id,
                start,
                app_servers: &app_servers,
                axum_router_lookup,
                plugin_backend,
                upstream_client_registry: &upstream_client_registry,
                request_drop: Arc::clone(&request_drop),
                request_log: send_request_log_if_enabled,
                #[cfg(feature = "mesh")]
                serverless_manager: &serverless_manager,
                #[cfg(feature = "mesh")]
                mesh_transport: &mesh_transport,
                #[cfg(feature = "mesh")]
                mesh_backend_pool: &mesh_backend_pool,
            },
            |method, url, headers, body, timeout| {
                let url = url.to_string();
                let headers = headers.cloned();
                Box::pin(async move {
                    crate::http_client::send_request_via_quic_tunnel(
                        method,
                        &url,
                        headers.as_ref(),
                        body,
                        timeout,
                    )
                    .await
                })
            },
            |body, site_id, last_modified, poison_config| async move {
                crate::http::apply_image_poisoning(body, site_id, last_modified, poison_config)
                    .await
            },
            crate::metrics::record_http_request_latency,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mesh::proxy::get_cached_regex;
    use synvoid_http::response_transform::path_looks_like_image;

    #[test]
    fn test_is_valid_http_request_start_valid_methods() {
        for method in HTTP_VALID_METHODS {
            let request = format!("{} / HTTP/1.1\r\n", method);
            assert!(
                is_valid_http_request_start(request.as_bytes()),
                "Should recognize valid method: {}",
                method
            );
        }
    }

    #[test]
    fn test_is_valid_http_request_start_invalid() {
        assert!(!is_valid_http_request_start(b""));
        assert!(!is_valid_http_request_start(b"GET"));
        assert!(!is_valid_http_request_start(b"GET/ HTTP/1.1"));
        assert!(!is_valid_http_request_start(b"INVALID / HTTP/1.1\r\n"));
    }

    #[test]
    fn test_is_valid_http_request_start_with_query() {
        assert!(is_valid_http_request_start(
            b"POST /path?query=value HTTP/1.1\r\n"
        ));
        assert!(is_valid_http_request_start(
            b"GET /api/users?id=123 HTTP/1.0\r\n"
        ));
    }

    #[test]
    fn test_is_tls_client_hello_valid() {
        let tls_hello = [0x16, 0x03, 0x00];
        assert!(is_tls_client_hello(&tls_hello));

        let tls_hello = [0x16, 0x03, 0x01];
        assert!(is_tls_client_hello(&tls_hello));

        let tls_hello = [0x16, 0x03, 0x03];
        assert!(is_tls_client_hello(&tls_hello));
    }

    #[test]
    fn test_is_tls_client_hello_invalid() {
        assert!(!is_tls_client_hello(b"GET / HTTP/1.1"));
        assert!(!is_tls_client_hello(&[0x16, 0x03, 0x04]));
        assert!(!is_tls_client_hello(&[0x15]));
        assert!(!is_tls_client_hello(&[]));
        assert!(!is_tls_client_hello(&[0x16, 0x04]));
    }

    #[test]
    fn test_is_tls_client_hello_minimum_length() {
        assert!(!is_tls_client_hello(&[0x16, 0x03]));
        assert!(!is_tls_client_hello(&[0x16]));
        assert!(!is_tls_client_hello(&[]));
    }

    #[test]
    fn test_protocol_validating_stream_initial_bytes() {
        let stream = ProtocolValidatingStream::<std::io::Cursor<Vec<u8>>>::new(
            std::io::Cursor::new(vec![]),
            b"Hello World".to_vec(),
        );
        assert_eq!(stream.initial_bytes.as_ref().map(|s| s.len()), Some(11));
    }

    #[test]
    fn test_get_cached_regex_valid_pattern() {
        let pattern = r"\.(?:jpe?g|png|gif)$";
        let regex = get_cached_regex(pattern);
        assert!(regex.is_some());

        let regex2 = get_cached_regex(pattern);
        assert!(regex2.is_some());
    }

    #[test]
    fn test_get_cached_regex_invalid_pattern() {
        let pattern = r"[";
        let regex = get_cached_regex(pattern);
        assert!(regex.is_none());
    }

    #[test]
    fn test_get_cached_regex_caches_result() {
        let pattern = r"test\d+";
        let regex1 = get_cached_regex(pattern);
        let regex2 = get_cached_regex(pattern);
        assert!(regex1.is_some());
        assert!(regex2.is_some());
        assert_eq!(
            regex1.map(|r| r.as_str().to_string()),
            regex2.map(|r| r.as_str().to_string())
        );
    }

    #[test]
    fn test_image_protection_regex_matches() {
        assert!(path_looks_like_image("/image.jpg"));
        assert!(path_looks_like_image("/image.jpeg"));
        assert!(path_looks_like_image("/image.png"));
        assert!(path_looks_like_image("/image.gif"));
        assert!(path_looks_like_image("/image.webp"));
        assert!(path_looks_like_image("/image.bmp"));
        assert!(path_looks_like_image("/image.svg"));
        assert!(path_looks_like_image("/image.ico"));
        assert!(path_looks_like_image("/image.jpg?querystring"));
    }

    #[test]
    fn test_image_protection_regex_no_match() {
        assert!(!path_looks_like_image("/image.txt"));
        assert!(!path_looks_like_image("/image.html"));
        assert!(!path_looks_like_image("/image"));
        assert!(!path_looks_like_image("/jpeg"));
        assert!(!path_looks_like_image("/image.png#anchor"));
    }
}
