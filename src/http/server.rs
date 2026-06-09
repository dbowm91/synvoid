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

use crate::waf::WafCore;
use crate::worker::drain_state::WorkerDrainState;
use synvoid_config::http::HttpConfig;
use synvoid_config::MainConfig;
use synvoid_http::RequestPreparationOutcome;
use synvoid_http_client::ErasedHttpClient;
use synvoid_metrics::WorkerMetrics;
use synvoid_proxy::Router;
use synvoid_proxy::UpstreamClientRegistry;
use synvoid_waf::{FloodDecision, FloodProtector};

#[allow(unused_imports)]
use synvoid_http_client::{create_http_client_with_config, HttpClient};
#[cfg(feature = "mesh")]
use synvoid_mesh::config::MeshConfig;
#[cfg(feature = "mesh")]
use synvoid_mesh::transports::MeshTransportManager;
#[cfg(feature = "mesh")]
use synvoid_mesh::MeshBackendPool;
use tokio::sync::RwLock;

mod accept_loop;
mod connection_types;
mod observability;

pub(crate) use observability::send_request_log_if_enabled;

use connection_types::*;

/// Per-tenant backend handles that are each owned by a different subsystem
/// (serverless runtime, app-server supervisor map, plugin manager).
///
/// Grouped separately from `HttpServerRuntime` so the per-request call
/// site can read `runtime.backends.serverless` rather than threading
/// three independent `Option<Arc<...>>` fields. Each field is
/// independently `None`/replaceable.
#[derive(Clone, Default)]
pub(crate) struct HttpAppBackends {
    pub serverless_manager: Option<Arc<crate::serverless::manager::ServerlessManager>>,
    pub app_servers:
        Option<Arc<RwLock<HashMap<String, Arc<crate::app_server::GranianSupervisor>>>>>,
    /// Type-erased handle to the root `PluginManager`. Cast to
    /// `&dyn synvoid_http::WasmFilterBackend` and
    /// `&dyn synvoid_http::AxumDynamicRouterLookup` at the use site
    /// (the existing `downcast_ref` pattern at server.rs:309, 313).
    pub plugin_manager: Option<Arc<dyn std::any::Any + Send + Sync>>,
}

/// Composition struct that groups the long-lived "what the HTTP server
/// has" dependencies into a single cloneable bag. Introduced in RHP-S03
/// so that `run_accept_loop` and `HttpServer::handle_request` can take
/// one `HttpServerRuntime` parameter instead of 20+ concrete parameters,
/// and so that the accept loop clones the bag once per connection
/// instead of cloning each dependency once per connection.
///
/// Root-only (per `plans/server_runtime_context_design.md` §3.1):
/// `WafCore`, `WorkerDrainState`, `FloodProtector`, and `PluginManager`
/// (via `dyn Any`) all live in root.
#[derive(Clone)]
pub(crate) struct HttpServerRuntime {
    pub router: Arc<Router>,
    pub waf: Arc<WafCore>,
    pub flood_protector: Option<Arc<FloodProtector>>,
    pub client: HttpClient,
    pub http_config: HttpConfig,
    pub alt_svc: Option<String>,
    pub main_config: Arc<MainConfig>,
    pub drain_state: Option<Arc<WorkerDrainState>>,
    pub metrics: Option<Arc<WorkerMetrics>>,
    pub ipc: Option<Arc<tokio::sync::Mutex<crate::process::ipc_transport::IpcStream>>>,
    pub worker_id: Option<crate::process::ipc::WorkerId>,
    pub connection_limit: Arc<Semaphore>,
    pub upstream_client_registry: Arc<UpstreamClientRegistry>,
    pub erased_http_client: ErasedHttpClient,
    pub backends: HttpAppBackends,
    #[cfg(feature = "mesh")]
    pub mesh_config: Option<Arc<MeshConfig>>,
    #[cfg(feature = "mesh")]
    pub mesh_transport: Option<Arc<MeshTransportManager>>,
    #[cfg(feature = "mesh")]
    pub mesh_backend_pool: Option<Arc<MeshBackendPool>>,
}

pub struct HttpServer {
    addr: SocketAddr,
    shutdown_rx: broadcast::Receiver<()>,
    runtime: HttpServerRuntime,
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

        let runtime = HttpServerRuntime {
            router: Arc::new(router),
            waf,
            flood_protector: None,
            client,
            http_config,
            alt_svc: None,
            main_config: Arc::new(main_config),
            drain_state: None,
            metrics: None,
            ipc: None,
            worker_id: None,
            connection_limit: Arc::new(Semaphore::new(max_connections)),
            upstream_client_registry: Arc::new(UpstreamClientRegistry::new()),
            erased_http_client: ErasedHttpClient::new(100),
            backends: HttpAppBackends::default(),
            #[cfg(feature = "mesh")]
            mesh_config: None,
            #[cfg(feature = "mesh")]
            mesh_transport: None,
            #[cfg(feature = "mesh")]
            mesh_backend_pool: None,
        };

        Self {
            addr,
            shutdown_rx,
            runtime,
        }
    }

    pub fn with_serverless_manager(
        mut self,
        manager: Arc<crate::serverless::manager::ServerlessManager>,
    ) -> Self {
        self.runtime.backends.serverless_manager = Some(manager);
        self
    }

    pub fn with_metrics(mut self, metrics: Arc<WorkerMetrics>) -> Self {
        self.runtime.metrics = Some(metrics);
        self
    }

    pub fn with_ipc(
        mut self,
        ipc: Arc<tokio::sync::Mutex<crate::process::ipc_transport::IpcStream>>,
        worker_id: crate::process::ipc::WorkerId,
    ) -> Self {
        self.runtime.ipc = Some(ipc);
        self.runtime.worker_id = Some(worker_id);
        self
    }

    pub fn with_flood_protector(mut self, flood_protector: Arc<FloodProtector>) -> Self {
        self.runtime.flood_protector = Some(flood_protector);
        self
    }

    pub fn with_alt_svc(mut self, alt_svc: String) -> Self {
        self.runtime.alt_svc = Some(alt_svc);
        self
    }

    pub fn with_drain_state(mut self, drain_state: Arc<WorkerDrainState>) -> Self {
        self.runtime.drain_state = Some(drain_state);
        self
    }

    #[cfg(feature = "mesh")]
    pub fn with_mesh_config(mut self, mesh_config: Option<Arc<MeshConfig>>) -> Self {
        self.runtime.mesh_config = mesh_config;
        self
    }

    #[cfg(feature = "mesh")]
    pub fn with_mesh_transport(mut self, transport: Option<Arc<MeshTransportManager>>) -> Self {
        self.runtime.mesh_transport = transport;
        self
    }

    pub fn with_app_servers(
        mut self,
        app_servers: Option<
            Arc<RwLock<HashMap<String, Arc<crate::app_server::GranianSupervisor>>>>,
        >,
    ) -> Self {
        self.runtime.backends.app_servers = app_servers;
        self
    }

    #[cfg(feature = "mesh")]
    pub fn with_mesh_backend_pool(mut self, pool: Option<Arc<MeshBackendPool>>) -> Self {
        self.runtime.mesh_backend_pool = pool;
        self
    }

    #[cfg(feature = "mesh")]
    pub async fn serve(self) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        accept_loop::run_accept_loop(self.addr, self.shutdown_rx, self.runtime).await
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
            drain_state.clone(),
            Arc::clone(&router),
            Arc::clone(&waf),
            alt_svc.clone(),
            Arc::clone(&main_config),
            http_config.clone(),
            metrics.clone(),
            ipc.clone(),
            worker_id,
            start,
            Arc::clone(&request_drop),
            send_request_log_if_enabled,
            #[cfg(feature = "mesh")]
            mesh_config.clone(),
            #[cfg(feature = "mesh")]
            mesh_transport.clone(),
            #[cfg(feature = "mesh")]
            serverless_manager.clone(),
            Arc::clone(&upstream_client_registry),
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
        let plugin_backend_arc: Option<Arc<dyn synvoid_http::WasmFilterBackend + Send + Sync>> =
            router
                .plugin_manager()
                .and_then(|pm| {
                    let arc_any: Arc<dyn std::any::Any + Send + Sync> = Arc::clone(pm);
                    arc_any.downcast::<crate::plugin::PluginManager>().ok()
                })
                .map(|arc| arc as Arc<dyn synvoid_http::WasmFilterBackend + Send + Sync>);
        let axum_router_lookup_arc: Option<
            Arc<dyn synvoid_http::AxumDynamicRouterLookup + Send + Sync>,
        > = router
            .plugin_manager()
            .and_then(|pm| {
                let arc_any: Arc<dyn std::any::Any + Send + Sync> = Arc::clone(pm);
                arc_any.downcast::<crate::plugin::PluginManager>().ok()
            })
            .map(|arc| arc as Arc<dyn synvoid_http::AxumDynamicRouterLookup + Send + Sync>);

        synvoid_http::handle_http_request_postlude(
            synvoid_http::HttpRequestPostludeContext {
                prepared,
                client_ip,
                router: Arc::clone(&router),
                waf: Arc::clone(&waf),
                client: client.clone(),
                alt_svc: alt_svc.clone(),
                main_config: Arc::clone(&main_config),
                http_config: http_config.clone(),
                metrics: metrics.clone(),
                ipc: ipc.clone(),
                worker_id,
                start,
                app_servers: app_servers.clone(),
                axum_router_lookup: axum_router_lookup_arc,
                plugin_backend: plugin_backend_arc,
                upstream_client_registry: Arc::clone(&upstream_client_registry),
                request_drop: Arc::clone(&request_drop),
                request_log: send_request_log_if_enabled,
                #[cfg(feature = "mesh")]
                serverless_manager: serverless_manager.clone(),
                #[cfg(feature = "mesh")]
                mesh_transport: mesh_transport.clone(),
                #[cfg(feature = "mesh")]
                mesh_backend_pool: mesh_backend_pool.clone(),
            },
            |method, url, headers, body, timeout| {
                let url = url.to_string();
                let headers = headers;
                Box::pin(async move {
                    crate::http_client::send_request_via_quic_tunnel(
                        method, &url, headers, body, timeout,
                    )
                    .await
                })
            },
            |body, site_id, last_modified, rights_config| async move {
                synvoid_static_files::image_rights::apply_image_rights_marking(
                    body,
                    site_id,
                    last_modified,
                    rights_config,
                )
                .await
            },
            synvoid_metrics::record_http_request_latency,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use synvoid_http::response_transform::path_looks_like_image;
    use synvoid_mesh::proxy::get_cached_regex;

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
