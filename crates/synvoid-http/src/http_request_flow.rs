use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use synvoid_config::{HttpConfig, MainConfig};
use synvoid_metrics::WorkerMetrics;
use synvoid_proxy::client_registry::UpstreamClientRegistry;
use synvoid_proxy::Router;
use tokio::sync::Mutex;

use crate::request_frontdoor::{
    prepare_request_frontdoor, RequestFrontdoorContext, RequestFrontdoorOutcome,
};
use crate::request_preparation::{
    prepare_request_after_preflight, prepare_request_preflight, RequestPreflight,
    RequestPreflightOutcome, RequestPreparationOutcome,
};
use crate::streaming_request_fast_path::StreamingRequestFastPathOutcome;
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
    drain_state: Option<Arc<D>>,
    router: Arc<Router>,
    waf: Arc<W>,
    alt_svc: Option<String>,
    main_config: Arc<MainConfig>,
    http_config: HttpConfig,
    metrics: Option<Arc<WorkerMetrics>>,
    ipc: Option<Arc<Mutex<synvoid_ipc::AsyncIpcStream>>>,
    worker_id: Option<synvoid_ipc::WorkerId>,
    start: Instant,
    request_drop: Arc<dyn Fn() + Send + Sync>,
    request_log: RequestLogFn,
    #[cfg(feature = "mesh")] mesh_config: Option<Arc<synvoid_mesh::MeshConfig>>,
    #[cfg(feature = "mesh")] mesh_transport: Option<
        Arc<synvoid_mesh::transports::MeshTransportManager>,
    >,
    #[cfg(feature = "mesh")] _serverless_manager: Option<
        Arc<synvoid_serverless::ServerlessManager>,
    >,
    _upstream_client_registry: Arc<UpstreamClientRegistry>,
) -> Result<HttpRequestFlowOutcome, hyper::Error>
where
    W: BufferedRequestWaf + crate::RequestBodyWaf + Send + Sync + 'static,
    D: HttpDrainControl + Send + Sync + 'static,
{
    let request_preparation_started_at = Instant::now();
    let alt_svc_for_frontdoor = alt_svc.clone();
    let main_config_for_frontdoor = Arc::clone(&main_config);
    let frontdoor = match prepare_request_frontdoor(RequestFrontdoorContext {
        req,
        client_ip,
        local_addr,
        drain_state,
        alt_svc: alt_svc_for_frontdoor,
        main_config: main_config_for_frontdoor,
        #[cfg(feature = "mesh")]
        mesh_config,
        #[cfg(feature = "mesh")]
        mesh_transport,
    })
    .await?
    {
        RequestFrontdoorOutcome::Continue(frontdoor) => frontdoor,
        RequestFrontdoorOutcome::Respond(response) => {
            record_request_preparation_phase(
                &metrics,
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

    let alt_svc_for_traffic = alt_svc.clone();
    let main_config_for_traffic_fn = Arc::clone(&main_config);
    let main_config_for_traffic_cb = Arc::clone(&main_config);
    let ipc_for_traffic = ipc.clone();
    let conn_guard = match maybe_enforce_request_traffic_limits(
        waf.connection_limiter(),
        client_ip,
        path.clone(),
        start,
        waf.is_over_bandwidth_limit(),
        alt_svc_for_traffic,
        main_config_for_traffic_fn,
        move |status, latency_ms, site_id, method, path, user_agent, is_internal| {
            request_log(
                ipc_for_traffic.clone(),
                worker_id,
                &main_config_for_traffic_cb,
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
            record_request_preparation_phase(
                &metrics,
                synvoid_metrics::WorkerInlineCpuPhase::RequestPreparation,
                request_preparation_started_at,
            );
            return Ok(HttpRequestFlowOutcome {
                client_ip,
                outcome: RequestPreparationOutcome::Respond(response),
            });
        }
    };

    let alt_svc_for_preflight = alt_svc.clone();
    let main_config_for_preflight_fn = Arc::clone(&main_config);
    let main_config_for_preflight_cb = Arc::clone(&main_config);
    let router_for_preflight = Arc::clone(&router);
    let waf_for_preflight = Arc::clone(&waf);
    let ipc_for_preflight = ipc.clone();
    let preflight = match prepare_request_preflight(
        frontdoor_req,
        client_ip,
        local_addr,
        router_for_preflight,
        waf_for_preflight,
        alt_svc_for_preflight,
        main_config_for_preflight_fn,
        move |status, site_id, bypassed, method, path, user_agent| {
            request_log(
                ipc_for_preflight.clone(),
                worker_id,
                &main_config_for_preflight_cb,
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
            record_request_preparation_phase(
                &metrics,
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
    let handle_pass =
        move |body| async move { Ok(StreamingRequestFastPathOutcome::Continue(body)) };

    let alt_svc_for_after = alt_svc;
    let main_config_for_after = main_config;
    let metrics_for_after = metrics.clone();
    let ipc_for_after_limit = ipc.clone();
    let main_config_for_after_limit = Arc::clone(&main_config_for_after);
    let ipc_for_after_final = ipc.clone();
    let main_config_for_after_final = Arc::clone(&main_config_for_after);
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
        waf,
        main_config_for_after,
        http_config,
        metrics_for_after,
        alt_svc_for_after,
        conn_guard,
        start,
        move |status, latency_ms, site_id, method, path, user_agent, is_internal| {
            request_log(
                ipc_for_after_limit.clone(),
                worker_id,
                &main_config_for_after_limit,
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
        move |status, bypassed| {
            request_log(
                ipc_for_after_final.clone(),
                worker_id,
                &main_config_for_after_final,
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

    record_request_preparation_phase(
        &metrics,
        synvoid_metrics::WorkerInlineCpuPhase::RequestPreparation,
        request_preparation_started_at,
    );

    Ok(HttpRequestFlowOutcome { client_ip, outcome })
}

fn record_request_preparation_phase(
    metrics: &Option<Arc<WorkerMetrics>>,
    phase: synvoid_metrics::WorkerInlineCpuPhase,
    started_at: Instant,
) {
    if let Some(metrics) = metrics {
        metrics.record_inline_cpu_phase_time_ms(phase, started_at.elapsed().as_millis() as u64);
    }
}
