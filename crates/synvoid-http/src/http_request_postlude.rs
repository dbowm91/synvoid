use std::collections::HashMap;
use std::convert::Infallible;
use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::Bytes;
use http::Response;
use http_body_util::combinators::BoxBody;
use tokio::sync::{Mutex, RwLock};

use synvoid_app_server::GranianSupervisor;
use synvoid_config::{HttpConfig, MainConfig};
use synvoid_metrics::bandwidth::{BandwidthProtocol, EgressDirection};
use synvoid_metrics::{WorkerInlineCpuPhase, WorkerMetrics};
use synvoid_proxy::client_registry::UpstreamClientRegistry;
use synvoid_proxy::protocol::trait_def::WafCoreBackend;
use synvoid_proxy::{BackendType, Router};

use crate::backend_dispatch::{
    handle_pass_backend_dispatch, BackendDispatchContext, BackendDispatchMetrics,
};
use crate::buffered_request_waf_dispatch::maybe_handle_buffered_request_waf;
use crate::http_request_flow::RequestLogFn;
use crate::request_preparation::PreparedRequest;
use crate::upload_validation_dispatch::UploadValidationWaf;
use crate::wasm_filter_dispatch::WafErrorPageRenderer;
use crate::BufferedRequestWaf;

#[derive(Clone)]
struct RequestMetricsAdapter {
    site_id: String,
    metrics: Arc<WorkerMetrics>,
}

impl RequestMetricsAdapter {
    fn record_start(&self) {
        self.metrics.record_site_request_start(&self.site_id);
    }

    fn record_blocked(&self) {
        self.metrics.record_site_blocked(&self.site_id);
    }

    fn record_challenged(&self) {
        self.metrics.record_site_challenged(&self.site_id);
    }

    fn record_proxied(&self) {
        self.metrics.record_site_proxied(&self.site_id);
    }

    fn record_upstream_success(&self) {
        self.metrics.record_site_upstream_success(&self.site_id);
    }

    fn record_upstream_failure(&self) {
        self.metrics.record_site_upstream_failure(&self.site_id);
    }

    fn record_request_end(&self, latency_ms: u64) {
        self.metrics
            .record_site_request_end(&self.site_id, latency_ms);
    }

    fn record_egress(&self, bytes: u64, direction: EgressDirection) {
        self.metrics
            .bandwidth
            .record_egress(bytes, BandwidthProtocol::Http, direction);
        self.metrics
            .bandwidth
            .record_site_egress(&self.site_id, bytes);
    }
}

impl BackendDispatchMetrics for RequestMetricsAdapter {
    fn record_proxied(&self) {
        self.record_proxied();
    }

    fn record_upstream_success(&self) {
        self.record_upstream_success();
    }

    fn record_upstream_failure(&self) {
        self.record_upstream_failure();
    }

    fn record_egress(&self, bytes: u64, direction: EgressDirection) {
        self.record_egress(bytes, direction);
    }
}

pub struct HttpRequestPostludeContext<W> {
    pub prepared: PreparedRequest,
    pub client_ip: IpAddr,
    pub router: Arc<Router>,
    pub waf: Arc<W>,
    pub client: synvoid_http_client::HttpClient,
    pub alt_svc: Option<String>,
    pub main_config: Arc<MainConfig>,
    pub http_config: HttpConfig,
    pub metrics: Option<Arc<WorkerMetrics>>,
    pub ipc: Option<Arc<Mutex<synvoid_ipc::AsyncIpcStream>>>,
    pub worker_id: Option<synvoid_ipc::WorkerId>,
    pub start: Instant,
    pub app_servers: Option<Arc<RwLock<HashMap<String, Arc<GranianSupervisor>>>>>,
    pub axum_router_lookup: Option<Arc<dyn crate::AxumDynamicRouterLookup + Send + Sync>>,
    pub plugin_backend: Option<Arc<dyn crate::WasmFilterBackend + Send + Sync>>,
    pub upstream_client_registry: Arc<UpstreamClientRegistry>,
    pub request_drop: Arc<dyn Fn() + Send + Sync>,
    pub request_log: RequestLogFn,
    #[cfg(feature = "mesh")]
    pub serverless_manager: Option<Arc<synvoid_serverless::ServerlessManager>>,
    #[cfg(feature = "mesh")]
    pub mesh_transport: Option<Arc<synvoid_mesh::mesh::transports::MeshTransportManager>>,
    #[cfg(feature = "mesh")]
    pub mesh_backend_pool: Option<Arc<synvoid_mesh::mesh::MeshBackendPool>>,
}

#[allow(clippy::too_many_arguments)]
pub async fn handle_http_request_postlude<
    W,
    QuicTunnelFn,
    MarkImageRightsFn,
    MarkImageRightsFut,
    RecordLatencyFn,
>(
    ctx: HttpRequestPostludeContext<W>,
    quic_tunnel_request: QuicTunnelFn,
    mark_image_rights: MarkImageRightsFn,
    record_http_request_latency: RecordLatencyFn,
) -> Result<Response<BoxBody<Bytes, Infallible>>, hyper::Error>
where
    W: BufferedRequestWaf
        + WafCoreBackend
        + UploadValidationWaf
        + WafErrorPageRenderer
        + Send
        + Sync
        + 'static,
    QuicTunnelFn: Fn(
            http::Method,
            &str,
            Option<http::HeaderMap>,
            Option<Bytes>,
            Option<Duration>,
        )
            -> futures::future::BoxFuture<'static, anyhow::Result<synvoid_http_client::HttpResponse>>
        + Send
        + 'static,
    MarkImageRightsFn: Fn(
            Bytes,
            String,
            Option<String>,
            Option<synvoid_config::site::SiteImageRightsConfig>,
        ) -> MarkImageRightsFut
        + Clone
        + Send
        + 'static,
    MarkImageRightsFut: std::future::Future<Output = Bytes> + Send + 'static,
    RecordLatencyFn: Fn(u64) + Send + 'static,
{
    let HttpRequestPostludeContext {
        prepared,
        client_ip,
        router,
        waf,
        client,
        alt_svc,
        main_config,
        http_config,
        metrics,
        ipc,
        worker_id,
        start,
        app_servers,
        axum_router_lookup,
        plugin_backend,
        upstream_client_registry,
        request_drop,
        request_log,
        #[cfg(feature = "mesh")]
        serverless_manager,
        #[cfg(feature = "mesh")]
        mesh_transport,
        #[cfg(feature = "mesh")]
        mesh_backend_pool,
    } = ctx;

    let PreparedRequest {
        on_upgrade,
        target,
        parts,
        method,
        path,
        user_agent,
        skip_waf,
        full_body_arc,
        request_body_size,
        body_slice,
    } = prepared;

    let site_id = target.site_id.to_string();
    let method_str = method.to_string();
    let target_for_waf = target.clone();
    let parts_for_waf = parts.clone();
    let query_string = parts_for_waf.uri.query();
    let headers_for_waf = parts_for_waf.headers.clone();
    let headers_for_waf_for_check = headers_for_waf.clone();
    let site_bot_config_for_waf = target_for_waf.site_config.bot.clone();
    let site_id_for_egress = site_id.clone();
    let site_id_for_log = site_id.clone();
    let method_str_for_log = method_str.clone();
    let path_for_log = path.clone();
    let user_agent_for_log = user_agent.clone();
    let user_agent_for_waf_check = user_agent.clone();

    let req_metrics = metrics.as_ref().map(|m| RequestMetricsAdapter {
        site_id: site_id.clone(),
        metrics: Arc::clone(m),
    });

    if let Some(ref rm) = req_metrics {
        rm.record_start();
    }
    if let Some(metrics) = &metrics {
        metrics.record_body_buffering_bytes(request_body_size);
    }

    let buffered_waf_started_at = Instant::now();
    let _body_slice_for_closure = body_slice.as_ref().map(|arc| arc.as_ref().clone());
    let site_id_for_closure = site_id.clone();
    let method_str_for_closure = method_str.clone();
    let path_for_closure = path.clone();
    let user_agent_for_closure = user_agent.clone();
    let headers_for_waf_for_check_for_closure = headers_for_waf_for_check.clone();
    let site_bot_config_for_waf_for_closure = site_bot_config_for_waf.clone();
    let query_string_for_closure = query_string.map(|s| s.to_string());
    let waf_for_closure = Arc::clone(&waf);
    if let Some(response) = maybe_handle_buffered_request_waf(
        target_for_waf,
        skip_waf,
        site_id.clone(),
        client_ip,
        method_str.clone(),
        path.clone(),
        query_string.map(|s| s.to_string()),
        headers_for_waf,
        body_slice.as_ref().map(|arc| arc.as_ref().clone()),
        user_agent_for_waf_check,
        http_config.clone(),
        alt_svc.clone(),
        Arc::clone(&main_config),
        move || {
            let waf = Arc::clone(&waf_for_closure);
            let site_id = site_id_for_closure.clone();
            let method_str = method_str_for_closure.clone();
            let path = path_for_closure.clone();
            let user_agent = user_agent_for_closure.clone();
            let headers_for_waf_for_check = headers_for_waf_for_check_for_closure.clone();
            let site_bot_config_for_waf = site_bot_config_for_waf_for_closure.clone();
            let query_string = query_string_for_closure.clone();
            async move {
                waf.check_request_full_owned(
                    Some(site_id),
                    client_ip,
                    method_str,
                    path,
                    query_string,
                    headers_for_waf_for_check,
                    None,
                    user_agent,
                    None,
                    Some(site_bot_config_for_waf),
                )
                .await
            }
        },
        {
            let request_drop = Arc::clone(&request_drop);
            move || {
                (request_drop.as_ref())();
            }
        },
        {
            let ipc = ipc.clone();
            let main_config = Arc::clone(&main_config);
            let site_id = site_id_for_log.clone();
            let method_str = method_str_for_log.clone();
            let path = path_for_log.clone();
            let user_agent = user_agent_for_log.clone();
            move |status, latency_ms| {
                request_log(
                    ipc.clone(),
                    worker_id,
                    &main_config,
                    client_ip,
                    &method_str,
                    &path,
                    status,
                    latency_ms,
                    &site_id,
                    user_agent.as_deref(),
                    false,
                );
            }
        },
        {
            let req_metrics = req_metrics.clone();
            move || {
                if let Some(ref rm) = req_metrics {
                    rm.record_blocked();
                }
            }
        },
        {
            let req_metrics = req_metrics.clone();
            let metrics = metrics.clone();
            let site_id_for_egress = site_id_for_egress.clone();
            move |body_len| {
                if let Some(ref rm) = req_metrics {
                    rm.record_egress(body_len, EgressDirection::Blocked);
                }
                if let Some(metrics) = &metrics {
                    metrics.bandwidth.record_egress(
                        body_len,
                        BandwidthProtocol::Http,
                        EgressDirection::Blocked,
                    );
                    metrics
                        .bandwidth
                        .record_site_egress(&site_id_for_egress, body_len);
                }
            }
        },
        {
            let req_metrics = req_metrics.clone();
            move |body_len| {
                if let Some(ref rm) = req_metrics {
                    rm.record_challenged();
                    rm.record_egress(body_len, EgressDirection::Challenged);
                }
            }
        },
        || start.elapsed().as_millis() as u64,
        {
            let waf = Arc::clone(&waf);
            move |status, message| waf.render_page_with_theme(status, Some(message), None)
        },
        {
            let waf = Arc::clone(&waf);
            move |tar_path| waf.generate_tarpit_response(tar_path)
        },
    )
    .await
    {
        record_inline_phase(
            &metrics,
            WorkerInlineCpuPhase::BufferedWaf,
            buffered_waf_started_at,
        );
        return Ok(response);
    }
    record_inline_phase(
        &metrics,
        WorkerInlineCpuPhase::BufferedWaf,
        buffered_waf_started_at,
    );

    let backend_dispatch_started_at = Instant::now();
    if let Some(ref rm) = req_metrics {
        rm.record_proxied();
    }

    let is_appserver = matches!(target.backend_type, BackendType::AppServer);
    let appserver_socket_path = if is_appserver {
        if let Some(servers) = app_servers.clone() {
            let servers_read = servers.read().await;
            servers_read
                .get(&site_id)
                .map(|supervisor| supervisor.config().resolve_socket_path())
        } else {
            None
        }
    } else {
        None
    };

    let backend_ctx = BackendDispatchContext {
        is_appserver,
        appserver_socket_path,
        app_servers,
        axum_router_lookup,
        plugin_backend,
        target,
        site_id: site_id.clone(),
        path: path.clone(),
        waf,
        client_ip,
        router,
        parts,
        method,
        full_body_arc,
        ipc: ipc.clone(),
        worker_id,
        main_config: Arc::clone(&main_config),
        method_str: method_str.clone(),
        start,
        user_agent: user_agent.clone(),
        alt_svc: alt_svc.clone(),
        req_metrics: req_metrics
            .clone()
            .map(|rm| Arc::new(rm) as Arc<dyn BackendDispatchMetrics>),
        metrics: metrics.clone(),
        request_body_size,
        body_slice,
        upstream_client_registry,
        client,
        #[cfg(feature = "mesh")]
        serverless_manager,
        #[cfg(feature = "mesh")]
        mesh_transport,
        #[cfg(feature = "mesh")]
        mesh_backend_pool,
    };

    let response = handle_pass_backend_dispatch(
        on_upgrade,
        backend_ctx,
        request_log,
        quic_tunnel_request,
        mark_image_rights,
    )
    .await?;

    record_inline_phase(
        &metrics,
        WorkerInlineCpuPhase::BackendDispatch,
        backend_dispatch_started_at,
    );

    let latency_ms = start.elapsed().as_millis() as u64;
    if let Some(ref rm) = req_metrics {
        rm.record_request_end(latency_ms);
    }
    record_http_request_latency(latency_ms);

    let status = response.status().as_u16();
    request_log(
        ipc,
        worker_id,
        &main_config,
        client_ip,
        &method_str,
        &path,
        status,
        latency_ms,
        &site_id,
        user_agent.as_deref(),
        false,
    );

    Ok(response)
}

fn record_inline_phase(
    metrics: &Option<Arc<WorkerMetrics>>,
    phase: WorkerInlineCpuPhase,
    started_at: Instant,
) {
    if let Some(metrics) = metrics {
        metrics.record_inline_cpu_phase_time_ms(phase, started_at.elapsed().as_millis() as u64);
    }
}
