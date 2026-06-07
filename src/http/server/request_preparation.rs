use super::*;

pub(super) use synvoid_http::{
    RequestPreflight, RequestPreflightOutcome, RequestPreparationOutcome,
};

pub(super) struct RequestPreparationContext<'a> {
    pub req: hyper::Request<hyper::body::Incoming>,
    pub client_ip: IpAddr,
    pub local_addr: Option<SocketAddr>,
    pub router: &'a Arc<Router>,
    pub waf: &'a Arc<WafCore>,
    pub alt_svc: &'a Option<String>,
    pub main_config: &'a Arc<MainConfig>,
    pub http_config: &'a HttpConfig,
    pub metrics: &'a Option<Arc<WorkerMetrics>>,
    pub http_conn: &'a HttpConnection,
    pub ipc: Option<Arc<tokio::sync::Mutex<crate::process::ipc_transport::IpcStream>>>,
    pub worker_id: Option<crate::process::ipc::WorkerId>,
    pub start: std::time::Instant,
    pub upstream_client_registry: &'a Arc<UpstreamClientRegistry>,
    #[cfg(feature = "mesh")]
    pub serverless_manager: &'a Option<Arc<crate::serverless::manager::ServerlessManager>>,
    pub conn_guard: Option<&'a ConnectionTokenGuard>,
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn prepare_request_before_buffered_waf(
    ctx: RequestPreparationContext<'_>,
) -> Result<RequestPreparationOutcome, hyper::Error> {
    let RequestPreparationContext {
        req,
        client_ip,
        local_addr,
        router,
        waf,
        alt_svc,
        main_config,
        http_config,
        metrics,
        http_conn,
        ipc,
        worker_id,
        start,
        upstream_client_registry,
        #[cfg(feature = "mesh")]
        serverless_manager,
        conn_guard,
    } = ctx;

    let waf_ref = waf.as_ref();
    let preflight = match synvoid_http::prepare_request_preflight(
        req,
        client_ip,
        local_addr,
        router,
        waf_ref,
        alt_svc,
        main_config,
        |status, site_id, bypassed, method, path, user_agent| {
            send_request_log_if_enabled(
                ipc.clone(),
                worker_id,
                main_config,
                client_ip,
                method,
                path,
                status,
                start.elapsed().as_millis() as u64,
                site_id,
                user_agent,
                bypassed,
            );
        },
        || {
            http_conn.request_drop();
        },
    )
    .await?
    {
        RequestPreflightOutcome::Continue(preflight) => preflight,
        RequestPreflightOutcome::Respond(response) => {
            return Ok(RequestPreparationOutcome::Respond(response));
        }
    };

    let RequestPreflight {
        on_upgrade,
        target,
        parts,
        body,
        method,
        path,
        host,
        user_agent,
        skip_waf,
    } = preflight;

    let site_id = target.site_id.to_string();
    let method_for_log = method.clone();
    let path_for_log = path.clone();
    let user_agent_for_log = user_agent.clone();
    let site_id_for_log = site_id.clone();
    let parts_for_pass = parts.clone();
    let target_for_pass = target.clone();

    let handle_pass = {
        let waf = Arc::clone(waf);
        let target = target_for_pass.clone();
        let parts = parts_for_pass.clone();
        let alt_svc = alt_svc.clone();
        let main_config = Arc::clone(main_config);
        #[cfg(feature = "mesh")]
        let serverless_manager = serverless_manager.clone();
        let upstream_client_registry = Arc::clone(upstream_client_registry);
        let ipc = ipc.clone();
        let user_agent_for_log = user_agent_for_log.clone();
        let method_for_log = method_for_log.clone();
        let path_for_log = path_for_log.clone();
        let site_id_for_log = site_id_for_log.clone();
        move |body| {
            let target = target.clone();
            let parts = parts.clone();
            let alt_svc = alt_svc.clone();
            let main_config = Arc::clone(&main_config);
            #[cfg(feature = "mesh")]
            let serverless_manager = serverless_manager.clone();
            let upstream_client_registry = Arc::clone(&upstream_client_registry);
            let ipc = ipc.clone();
            let user_agent_for_log = user_agent_for_log.clone();
            let method_for_log = method_for_log.clone();
            let path_for_log = path_for_log.clone();
            let site_id_for_log = site_id_for_log.clone();
            let streaming_waf = waf.streaming();
            async move {
                synvoid_http::handle_streaming_request_pass(
                    &target,
                    &path_for_log,
                    &method_for_log,
                    &parts,
                    body,
                    client_ip,
                    streaming_waf,
                    &alt_svc,
                    &main_config,
                    &upstream_client_registry,
                    #[cfg(feature = "mesh")]
                    serverless_manager.as_ref(),
                    |status| {
                        send_request_log_if_enabled(
                            ipc.clone(),
                            worker_id,
                            &main_config,
                            client_ip,
                            method_for_log.as_str(),
                            &path_for_log,
                            status,
                            start.elapsed().as_millis() as u64,
                            &site_id_for_log,
                            user_agent_for_log.as_deref(),
                            false,
                        );
                    },
                    || {
                        let body = waf.error_page_manager.render_page_with_theme(
                            403,
                            Some("Forbidden"),
                            target
                                .site_config
                                .error_pages
                                .theme
                                .as_ref()
                                .map(|theme_config| {
                                    theme_config.to_theme_config(waf.error_page_manager.theme())
                                })
                                .as_ref(),
                        );
                        crate::http::response_builder::build_response_with_alt_svc(
                            403,
                            body,
                            "text/html",
                            &alt_svc,
                            main_config.as_ref(),
                        )
                    },
                )
                .await
            }
        }
    };

    synvoid_http::prepare_request_after_preflight(
        RequestPreflight {
            on_upgrade,
            target,
            parts,
            body,
            method,
            path,
            host,
            user_agent,
            skip_waf,
        },
        client_ip,
        router,
        waf_ref,
        main_config,
        http_config,
        metrics,
        alt_svc,
        conn_guard,
        start,
        |status, latency_ms, site_id, method, path, user_agent, is_internal| {
            send_request_log_if_enabled(
                ipc.clone(),
                worker_id,
                main_config,
                client_ip,
                method,
                path,
                status,
                latency_ms,
                site_id,
                user_agent,
                is_internal,
            );
        },
        |status, bypassed| {
            send_request_log_if_enabled(
                ipc.clone(),
                worker_id,
                main_config,
                client_ip,
                method_for_log.as_str(),
                &path_for_log,
                status,
                start.elapsed().as_millis() as u64,
                &site_id_for_log,
                user_agent_for_log.as_deref(),
                bypassed,
            );
        },
        handle_pass,
        || http_conn.request_drop(),
    )
    .await
}
