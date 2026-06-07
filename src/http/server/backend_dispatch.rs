use super::*;

#[allow(clippy::too_many_arguments)]
pub(super) async fn handle_pass_backend_dispatch(
    on_upgrade: Option<hyper::upgrade::OnUpgrade>,
    dispatch_ctx: PassBackendDispatchContext<'_>,
) -> Result<Response<BoxBody<Bytes, Infallible>>, hyper::Error> {
    let plugin_backend = dispatch_ctx
        .router
        .plugin_manager()
        .and_then(|pm| pm.downcast_ref::<crate::plugin::PluginManager>())
        .map(|pm| pm as &dyn synvoid_http::WasmFilterBackend);
    let axum_router_lookup = dispatch_ctx
        .router
        .plugin_manager()
        .and_then(|pm| pm.downcast_ref::<crate::plugin::PluginManager>())
        .map(|pm| pm as &dyn synvoid_http::AxumDynamicRouterLookup);

    let is_appserver = matches!(
        dispatch_ctx.target.backend_type,
        crate::router::BackendType::AppServer
    );
    let appserver_socket_path = if is_appserver {
        if let Some(servers) = dispatch_ctx.app_servers {
            let servers_read = servers.read().await;
            servers_read
                .get(dispatch_ctx.site_id)
                .map(|supervisor| supervisor.config().resolve_socket_path())
        } else {
            None
        }
    } else {
        None
    };

    let backend_ctx = synvoid_http::BackendDispatchContext {
        is_appserver,
        appserver_socket_path,
        app_servers: dispatch_ctx.app_servers,
        axum_router_lookup,
        plugin_backend,
        target: dispatch_ctx.target,
        site_id: dispatch_ctx.site_id,
        path: dispatch_ctx.path,
        waf: dispatch_ctx.waf,
        client_ip: dispatch_ctx.client_ip,
        router: dispatch_ctx.router,
        parts: dispatch_ctx.parts,
        method: dispatch_ctx.method,
        full_body_arc: dispatch_ctx.full_body_arc,
        ipc: dispatch_ctx.ipc.clone(),
        worker_id: dispatch_ctx.worker_id,
        main_config: dispatch_ctx.main_config,
        method_str: dispatch_ctx.method_str,
        start: dispatch_ctx.start,
        user_agent: dispatch_ctx.user_agent,
        alt_svc: dispatch_ctx.alt_svc,
        req_metrics: dispatch_ctx
            .req_metrics
            .as_ref()
            .map(|rm| rm as &dyn synvoid_http::BackendDispatchMetrics),
        metrics: dispatch_ctx.metrics,
        request_body_size: dispatch_ctx.request_body_size,
        body_slice: dispatch_ctx.body_slice,
        upstream_client_registry: dispatch_ctx.upstream_client_registry,
        client: dispatch_ctx.client,
        #[cfg(feature = "mesh")]
        serverless_manager: dispatch_ctx.serverless_manager,
        #[cfg(feature = "mesh")]
        mesh_transport: dispatch_ctx.mesh_transport,
        #[cfg(feature = "mesh")]
        mesh_backend_pool: dispatch_ctx.mesh_backend_pool,
    };

    synvoid_http::handle_pass_backend_dispatch(
        on_upgrade,
        backend_ctx,
        send_request_log_if_enabled,
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
            crate::http::apply_image_poisoning(body, site_id, last_modified, poison_config).await
        },
    )
    .await
}
