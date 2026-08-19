use super::*;

struct HttpConnectionService {
    client_addr: SocketAddr,
    local_addr: Option<SocketAddr>,
    router: Arc<Router>,
    waf: Arc<WafCore>,
    client: HttpClient,
    alt_svc: Option<String>,
    main_config: Arc<MainConfig>,
    drain_state: Option<Arc<WorkerDrainState>>,
    http_config: HttpConfig,
    #[cfg(feature = "mesh")]
    mesh_config: Option<Arc<MeshConfig>>,
    #[cfg(feature = "mesh")]
    mesh_transport: Option<Arc<MeshTransportManager>>,
    metrics: Option<Arc<WorkerMetrics>>,
    http_conn: Arc<HttpConnection>,
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

impl hyper::service::Service<hyper::Request<hyper::body::Incoming>> for HttpConnectionService {
    type Response = Response<BoxBody<Bytes, Infallible>>;
    type Error = hyper::Error;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn call(&self, req: hyper::Request<hyper::body::Incoming>) -> Self::Future {
        let client_addr = self.client_addr;
        let local_addr = self.local_addr;
        let router = self.router.clone();
        let waf = self.waf.clone();
        let client = self.client.clone();
        let alt_svc = self.alt_svc.clone();
        let main_config = self.main_config.clone();
        let drain_state = self.drain_state.clone();
        let http_config = self.http_config.clone();
        #[cfg(feature = "mesh")]
        let mesh_config = self.mesh_config.clone();
        #[cfg(feature = "mesh")]
        let mesh_transport = self.mesh_transport.clone();
        let metrics = self.metrics.clone();
        let http_conn = self.http_conn.clone();
        let ipc = self.ipc.clone();
        let worker_id = self.worker_id;
        let serverless_manager = self.serverless_manager.clone();
        let connection_limit = self.connection_limit.clone();
        let app_servers = self.app_servers.clone();
        #[cfg(feature = "mesh")]
        let mesh_backend_pool = self.mesh_backend_pool.clone();
        let upstream_client_registry = self.upstream_client_registry.clone();
        let erased_http_client = self.erased_http_client.clone();

        Box::pin(async move {
            #[cfg(feature = "mesh")]
            {
                super::HttpServer::handle_request(
                    req,
                    client_addr,
                    local_addr,
                    router,
                    waf,
                    client,
                    alt_svc,
                    main_config,
                    drain_state,
                    http_config,
                    mesh_config,
                    mesh_transport,
                    metrics,
                    http_conn,
                    ipc,
                    worker_id,
                    serverless_manager,
                    connection_limit,
                    app_servers,
                    mesh_backend_pool,
                    upstream_client_registry,
                    erased_http_client,
                )
                .await
            }
            #[cfg(not(feature = "mesh"))]
            {
                super::HttpServer::handle_request(
                    req,
                    client_addr,
                    local_addr,
                    router,
                    waf,
                    client,
                    alt_svc,
                    main_config,
                    drain_state,
                    http_config,
                    metrics,
                    http_conn,
                    ipc,
                    worker_id,
                    serverless_manager,
                    connection_limit,
                    app_servers,
                    upstream_client_registry,
                    erased_http_client,
                )
                .await
            }
        })
    }
}

pub(super) async fn run_accept_loop(
    addr: SocketAddr,
    mut shutdown_rx: broadcast::Receiver<()>,
    runtime: HttpServerRuntime,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let std_listener = crate::platform::socket::bind_tcp_reuse(addr)?;
    let listener = TcpListener::from_std(std_listener)?;
    tracing::info!(
        "HTTP server listening on {} (HTTP/1.1 + HTTP/2) [SO_REUSEPORT]",
        addr
    );

    let header_read_timeout = Duration::from_secs(runtime.http_config.header_read_timeout_secs);
    let max_headers = runtime.http_config.max_headers;
    let max_buf_size = runtime.http_config.max_request_size;

    loop {
        tokio::select! {
            _ = shutdown_rx.recv() => {
                tracing::info!("HTTP server received shutdown signal");
                break;
            }
            result = listener.accept() => {
                match result {
                    Ok((stream, client_addr)) => {
                        let client_ip = client_addr.ip();

                        let local_addr = stream.local_addr().ok();

                        if let Some(ref fp) = runtime.flood_protector {
                            match fp.check_tcp_connection(client_ip) {
                                FloodDecision::Blackholed => {
                                    counter!("synvoid.http.flood_blackhole").increment(1);
                                    continue;
                                }
                                FloodDecision::RateLimited => {
                                    counter!("synvoid.http.flood_limited").increment(1);
                                    continue;
                                }
                                FloodDecision::Allowed => {}
                            }
                        }

                        let router = runtime.router.clone();
                        let waf = runtime.waf.clone();
                        let client = runtime.client.clone();
                        let alt_svc = runtime.alt_svc.clone();
                        let main_config = runtime.main_config.clone();
                        let drain_state = runtime.drain_state.clone();
                        let http_config = runtime.http_config.clone();
                        #[cfg(feature = "mesh")]
                        let mesh_config = runtime.mesh_config.clone();
                        #[cfg(feature = "mesh")]
                        let mesh_transport = runtime.mesh_transport.clone();
                        let metrics = runtime.metrics.clone();
                        let ipc = runtime.ipc.clone();
                        let worker_id = runtime.worker_id;
                        let serverless_manager = runtime.backends.serverless_manager.clone();
                        let connection_limit = runtime.connection_limit.clone();
                        let app_servers = runtime.backends.app_servers.clone();
                        #[cfg(feature = "mesh")]
                        let mesh_backend_pool = runtime.mesh_backend_pool.clone();
                        let upstream_client_registry = runtime.upstream_client_registry.clone();
                        let erased_http_client = runtime.erased_http_client.clone();

                        let (initial_bytes, stream_for_conn) = if http_config.strict_protocol_validation {
                            let mut peek_buf = [0u8; 16];
                            let mut stream_clone = stream;
                            match tokio::io::AsyncReadExt::read(&mut stream_clone, &mut peek_buf).await {
                                Ok(n) => {
                                    if n == 0 {
                                        continue;
                                    }
                                    if is_tls_client_hello(&peek_buf[..n]) {
                                        counter!("synvoid.http.tls_on_http_port").increment(1);
                                        tracing::debug!(
                                            "Rejected TLS connection on HTTP port from {}",
                                            client_ip
                                        );
                                        continue;
                                    }
                                    if !is_valid_http_request_start(&peek_buf[..n]) {
                                        counter!("synvoid.http.invalid_protocol").increment(1);
                                        tracing::debug!(
                                            "Rejected non-HTTP connection on HTTP port from {}",
                                            client_ip
                                        );
                                        continue;
                                    }
                                    (peek_buf[..n].to_vec(), stream_clone)
                                }
                                Err(_) => {
                                    continue;
                                }
                            }
                        } else {
                            (vec![], stream)
                        };

                        let http_conn = Arc::new(HttpConnection::new(stream_for_conn, initial_bytes));

                        let io = match http_conn.take_stream() {
                            Some(io) => io,
                            None => {
                                tracing::error!("Failed to take IO from HTTP connection");
                                continue;
                            }
                        };

                        let http_conn_for_task = http_conn.clone();
                        tokio::spawn(async move {
                            let http_conn_for_service = http_conn_for_task.clone();
                            let service = HttpConnectionService {
                                client_addr,
                                local_addr,
                                router,
                                waf,
                                client,
                                alt_svc,
                                main_config,
                                drain_state,
                                http_config,
                                #[cfg(feature = "mesh")]
                                mesh_config,
                                #[cfg(feature = "mesh")]
                                mesh_transport,
                                metrics,
                                http_conn: http_conn_for_service,
                                ipc,
                                worker_id,
                                serverless_manager,
                                connection_limit,
                                app_servers,
                                #[cfg(feature = "mesh")]
                                mesh_backend_pool,
                                upstream_client_registry,
                                erased_http_client,
                            };
                            let conn = hyper::server::conn::http1::Builder::new()
                                .header_read_timeout(header_read_timeout)
                                .max_headers(max_headers)
                                .max_buf_size(max_buf_size)
                                .serve_connection(io, service)
                                .with_upgrades();

                            if let Err(e) = conn.await {
                                tracing::debug!("HTTP connection error: {}", e);
                            }
                            if http_conn_for_task.should_drop() {
                                if let Some(stream) = http_conn_for_task.take_stream() {
                                    drop(stream);
                                }
                            }
                        });
                    }
                    Err(e) => {
                        tracing::error!("Accept error: {}", e);
                    }
                }
            }
        }
    }

    tracing::info!("HTTP server shutdown");

    Ok(())
}
