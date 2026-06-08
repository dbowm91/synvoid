use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use tokio::sync::Mutex;

use synvoid_config::{HttpConfig, MainConfig};
use synvoid_metrics::WorkerMetrics;
use synvoid_proxy::client_registry::UpstreamClientRegistry;
use synvoid_proxy::Router;

use crate::request_frontdoor::{
    prepare_request_frontdoor, RequestFrontdoorContext, RequestFrontdoorOutcome,
};
use crate::request_preparation::{
    prepare_request_after_preflight, prepare_request_preflight, RequestPreflight,
    RequestPreflightOutcome, RequestPreparationOutcome,
};
use crate::response_builder::build_response_with_alt_svc;
use crate::streaming_request_pass::handle_streaming_request_pass;
use crate::traffic_control::{maybe_enforce_request_traffic_limits, TrafficControlOutcome};
use crate::BufferedRequestWaf;
use crate::HttpDrainControl;

pub type RequestLogFn = fn(
    Option<Arc<Mutex<synvoid_ipc::AsyncIpcStream>>>,
    Option<synvoid_ipc::WorkerId>,
    &Arc<MainConfig>,
    IpAddr,
    &str,
    &str,
    u16,
    u64,
    &str,
    Option<&str>,
    bool,
);

pub struct HttpRequestFlowOutcome {
    pub client_ip: IpAddr,
    pub outcome: RequestPreparationOutcome,
}

#[allow(clippy::too_many_arguments)]
pub async fn prepare_http_request_flow<W, D>(
    req: hyper::Request<hyper::body::Incoming>,
    client_ip: IpAddr,
    local_addr: Option<SocketAddr>,
    drain_state: &Option<Arc<D>>,
    router: &Arc<Router>,
    waf: &Arc<W>,
    alt_svc: &Option<String>,
    main_config: &Arc<MainConfig>,
    http_config: &HttpConfig,
    metrics: &Option<Arc<WorkerMetrics>>,
    ipc: Option<Arc<Mutex<synvoid_ipc::AsyncIpcStream>>>,
    worker_id: Option<synvoid_ipc::WorkerId>,
    start: Instant,
    request_drop: Arc<dyn Fn() + Send + Sync>,
    request_log: RequestLogFn,
    #[cfg(feature = "mesh")] mesh_config: &Option<Arc<synvoid_mesh::MeshConfig>>,
    #[cfg(feature = "mesh")] mesh_transport: &Option<
        Arc<synvoid_mesh::transports::MeshTransportManager>,
    >,
    #[cfg(feature = "mesh")] serverless_manager: &Option<
        Arc<synvoid_serverless::ServerlessManager>,
    >,
    upstream_client_registry: &Arc<UpstreamClientRegistry>,
) -> Result<HttpRequestFlowOutcome, hyper::Error>
where
    W: BufferedRequestWaf + crate::RequestBodyWaf,
    D: HttpDrainControl,
{
    let request_preparation_started_at = Instant::now();
    let record_inline_phase = |phase: synvoid_metrics::WorkerInlineCpuPhase,
                               started_at: Instant| {
        if let Some(metrics) = &metrics {
            metrics.record_inline_cpu_phase_time_ms(phase, started_at.elapsed().as_millis() as u64);
        }
    };

    let frontdoor = match prepare_request_frontdoor(RequestFrontdoorContext {
        req,
        client_ip,
        local_addr,
        drain_state,
        alt_svc,
        main_config,
        #[cfg(feature = "mesh")]
        mesh_config,
        #[cfg(feature = "mesh")]
        mesh_transport,
    })
    .await?
    {
        RequestFrontdoorOutcome::Continue(frontdoor) => frontdoor,
        RequestFrontdoorOutcome::Respond(response) => {
            record_inline_phase(
                synvoid_metrics::WorkerInlineCpuPhase::RequestPreparation,
                request_preparation_started_at,
            );
            return Ok(HttpRequestFlowOutcome {
                client_ip,
                outcome: RequestPreparationOutcome::Respond(response),
            });
        }
    };

    let frontdoor_req = frontdoor.req;
    let client_ip = frontdoor.client_ip;
    let path = frontdoor.path;

    let conn_guard = match maybe_enforce_request_traffic_limits(
        waf.connection_limiter(),
        client_ip,
        &path,
        start,
        waf.is_over_bandwidth_limit(),
        alt_svc,
        main_config,
        |status, latency_ms, site_id, method, path, user_agent, is_internal| {
            request_log(
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
    )
    .await
    {
        TrafficControlOutcome::Continue { conn_guard } => conn_guard,
        TrafficControlOutcome::Respond(response) => {
            record_inline_phase(
                synvoid_metrics::WorkerInlineCpuPhase::RequestPreparation,
                request_preparation_started_at,
            );
            return Ok(HttpRequestFlowOutcome {
                client_ip,
                outcome: RequestPreparationOutcome::Respond(response),
            });
        }
    };

    let waf_ref = waf.as_ref();
    let preflight = match prepare_request_preflight(
        frontdoor_req,
        client_ip,
        local_addr,
        router,
        waf_ref,
        alt_svc,
        main_config,
        |status, site_id, bypassed, method, path, user_agent| {
            request_log(
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
        {
            let request_drop = Arc::clone(&request_drop);
            move || {
                (request_drop.as_ref())();
            }
        },
    )
    .await?
    {
        RequestPreflightOutcome::Continue(preflight) => preflight,
        RequestPreflightOutcome::Respond(response) => {
            record_inline_phase(
                synvoid_metrics::WorkerInlineCpuPhase::RequestPreparation,
                request_preparation_started_at,
            );
            return Ok(HttpRequestFlowOutcome {
                client_ip,
                outcome: RequestPreparationOutcome::Respond(response),
            });
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
                handle_streaming_request_pass(
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
                    &serverless_manager,
                    |status| {
                        request_log(
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
                        let body = waf.render_page_with_theme(
                            403,
                            Some("Forbidden"),
                            target
                                .site_config
                                .error_pages
                                .theme
                                .as_ref()
                                .map(|theme_config| {
                                    theme_config.to_theme_config(waf.error_page_theme())
                                })
                                .as_ref(),
                        );
                        build_response_with_alt_svc(
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

    let outcome = prepare_request_after_preflight(
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
        conn_guard.as_ref(),
        start,
        |status, latency_ms, site_id, method, path, user_agent, is_internal| {
            request_log(
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
            request_log(
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
        {
            let request_drop = Arc::clone(&request_drop);
            move || {
                (request_drop.as_ref())();
            }
        },
    )
    .await?;

    record_inline_phase(
        synvoid_metrics::WorkerInlineCpuPhase::RequestPreparation,
        request_preparation_started_at,
    );

    Ok(HttpRequestFlowOutcome { client_ip, outcome })
}
