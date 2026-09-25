use super::*;

#[allow(dead_code)]
pub(super) async fn run_accept_loop(
    addr: SocketAddr,
    mut shutdown_rx: broadcast::Receiver<()>,
    runtime: HttpServerRuntime,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let std_listener = synvoid_platform::socket_bind::bind_tcp_reuse(addr)?;
    let listener = TcpListener::from_std(std_listener)?;
    // Phase 76: plaintext H1 is driven by the qualified direct runtime
    // (no cleartext HTTP/2). The TLS listener keeps its own H1+H2 claim
    // because ALPN routing actually serves both.
    tracing::info!(
        "{}",
        crate::http::h1_policy::plaintext_startup_message(&addr)
    );

    // Phase 76: one shared EggServe policy/state for all plaintext H1
    // connections on this listener. Projection failure fails the listener
    // fast instead of failing per connection.
    let eggserve =
        crate::http::eggserve_h1::project_eggserve_h1(&runtime.http_config).map_err(|e| {
            Box::new(std::io::Error::other(format!(
                "eggserve H1 projection failed: {e}"
            ))) as Box<dyn std::error::Error + Send + Sync>
        })?;
    let eggserve_policy = eggserve.policy;
    let eggserve_state = eggserve.state;

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

                        // Phase 76: hand the caller-owned stream (with
                        // replayed peek bytes) to the EggServe direct H1
                        // driver. EggServe owns its Hyper adapter
                        // internally; SynVoid keeps socket/flood/sniff/
                        // admission/policy ownership around it.
                        let io = match http_conn.take_inner_stream() {
                            Some(io) => io,
                            None => {
                                tracing::error!("Failed to take IO from HTTP connection");
                                continue;
                            }
                        };

                        let conn_shutdown =
                            eggserve_server::ConnectionShutdown::new();

                        let service_ctx = crate::http::service_core::NeutralServiceContext {
                            router,
                            waf,
                            alt_svc,
                            main_config,
                            http_config,
                            metrics,
                            ipc,
                            worker_id,
                            drain_state: drain_state.clone(),
                            upstream_client_registry,
                            connection_limit,
                            app_servers,
                            #[cfg(feature = "mesh")]
                            mesh_config,
                            #[cfg(feature = "mesh")]
                            mesh_transport,
                            #[cfg(feature = "mesh")]
                            mesh_backend_pool,
                            serverless_manager,
                        };
                        let service = crate::http::eggserve_h1::EggserveH1Service::new(
                            service_ctx,
                            conn_shutdown.clone(),
                            None,
                            synvoid_proxy::ForwardedProtocol::Http,
                            local_addr,
                            drain_state.clone(),
                        );
                        let policy = eggserve_policy.clone();
                        let state = eggserve_state.clone();
                        let context =
                            eggserve_server::ConnectionContext::for_tcp(
                                local_addr.unwrap_or(client_addr),
                                client_addr,
                                None,
                            );
                        let mut worker_shutdown = shutdown_rx.resubscribe();
                        let http_conn_for_task = http_conn.clone();
                        tokio::spawn(async move {
                            // The service bridges WAF request-drop to
                            // `conn_shutdown`; worker shutdown arrives here.
                            tokio::select! {
                                outcome = eggserve_server::serve_http1_connection_with_policy(
                                    io,
                                    service,
                                    policy,
                                    context,
                                    state,
                                    &conn_shutdown,
                                ) => {
                                    tracing::debug!("HTTP connection outcome: {:?}", outcome);
                                }
                                _ = worker_shutdown.recv() => {
                                    // Worker/server shutdown closes the
                                    // connection; in-flight responses drain
                                    // per the bounded post-shutdown budget.
                                    conn_shutdown.shutdown();
                                }
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
