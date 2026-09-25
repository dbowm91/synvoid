//! Shared neutral request core (Phase 75).
//!
//! Both H1 lanes — the Hyper transport adapter and the EggServe direct
//! service — convert their ingress into
//! [`synvoid_http::inbound::InboundRequest`] and invoke
//! [`handle_neutral_request`]. There is exactly one request
//! policy/backend implementation; the lanes differ only in transport
//! capture, admission bridging, and connection shutdown.

use std::collections::HashMap;
use std::convert::Infallible;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use http::Response;
use http_body_util::combinators::BoxBody;
use tokio::sync::{RwLock, Semaphore};

use synvoid_config::http::HttpConfig;
use synvoid_config::MainConfig;
use synvoid_http::inbound::InboundRequest;
use synvoid_http::RequestPreparationOutcome;
use synvoid_metrics::WorkerMetrics;
use synvoid_proxy::{ForwardedProtocol, Router, UpstreamClientRegistry};

/// Shared per-request context for the neutral pipeline. Cheap to assemble
/// per request from server-owned Arcs; carries no transport state.
#[derive(Clone)]
pub struct NeutralServiceContext<W, D> {
    pub router: Arc<Router>,
    pub waf: Arc<W>,
    pub alt_svc: Option<String>,
    pub main_config: Arc<MainConfig>,
    pub http_config: HttpConfig,
    pub metrics: Option<Arc<WorkerMetrics>>,
    pub ipc: Option<Arc<tokio::sync::Mutex<crate::process::ipc_transport::IpcStream>>>,
    pub worker_id: Option<crate::process::ipc::WorkerId>,
    pub drain_state: Option<Arc<D>>,
    pub upstream_client_registry: Arc<UpstreamClientRegistry>,
    pub connection_limit: Arc<Semaphore>,
    #[allow(clippy::type_complexity)]
    // reason: nested Arc<RwLock<HashMap<...>>> composition root type (mirrors postlude context)
    pub app_servers:
        Option<Arc<RwLock<HashMap<String, Arc<crate::app_server::GranianSupervisor>>>>>,
    #[cfg(feature = "mesh")]
    pub mesh_config: Option<Arc<synvoid_mesh::config::MeshConfig>>,
    #[cfg(feature = "mesh")]
    pub mesh_transport: Option<Arc<synvoid_mesh::transports::MeshTransportManager>>,
    #[cfg(feature = "mesh")]
    pub mesh_backend_pool: Option<Arc<synvoid_mesh::MeshBackendPool>>,
    pub serverless_manager: Option<Arc<crate::serverless::manager::ServerlessManager>>,
}

/// Run one neutral request through the canonical flow + postlude.
///
/// `request_drop` is the lane's drop callback (Hyper connection flag vs
/// EggServe per-connection shutdown); `forwarded_protocol`/`ja4_hash`
/// describe the lane. Admission (`connection_limit`) stays SynVoid-owned
/// here for both lanes.
#[allow(clippy::too_many_arguments)]
pub async fn handle_neutral_request<W, D>(
    ctx: &NeutralServiceContext<W, D>,
    inbound: InboundRequest,
    client_ip: IpAddr,
    local_addr: Option<SocketAddr>,
    request_drop: Arc<dyn Fn() + Send + Sync>,
    ja4_hash: Option<String>,
    forwarded_protocol: ForwardedProtocol,
    drain_guard_state: Option<Arc<crate::worker::drain_state::WorkerDrainState>>,
) -> Result<Response<BoxBody<Bytes, Infallible>>, hyper::Error>
where
    W: synvoid_http::BufferedRequestWaf
        + synvoid_http::RequestBodyWaf
        + synvoid_proxy::protocol::trait_def::WafCoreBackend
        + synvoid_http::UploadValidationWaf
        + synvoid_http::WafErrorPageRenderer
        + Send
        + Sync
        + 'static,
    D: synvoid_http::internal_handlers::HttpDrainControl + Send + Sync + 'static,
{
    let request_queue_started_at = Instant::now();
    let _drain_guard = super::server::DrainGuard::new(drain_guard_state);
    let _permit = match ctx.connection_limit.clone().acquire_owned().await {
        Ok(p) => p,
        Err(_) => {
            tracing::error!("Connection limit semaphore closed");
            return Ok(synvoid_http::response_builder::build_response_with_alt_svc(
                503,
                "Service Unavailable".to_string(),
                "text/plain",
                &ctx.alt_svc,
                &ctx.main_config,
            ));
        }
    };
    let request_queue_time_ms = request_queue_started_at.elapsed().as_millis() as u64;
    if let Some(metrics) = &ctx.metrics {
        metrics.record_request_queue_time_ms(request_queue_time_ms);
    }

    let start = Instant::now();
    let flow = synvoid_http::prepare_http_request_flow(
        inbound,
        client_ip,
        local_addr,
        ctx.drain_state.clone(),
        Arc::clone(&ctx.router),
        Arc::clone(&ctx.waf),
        ctx.alt_svc.clone(),
        Arc::clone(&ctx.main_config),
        ctx.http_config.clone(),
        ctx.metrics.clone(),
        ctx.ipc.clone(),
        ctx.worker_id,
        start,
        Arc::clone(&request_drop),
        super::server::send_request_log_if_enabled,
        #[cfg(feature = "mesh")]
        ctx.mesh_config.clone(),
        #[cfg(feature = "mesh")]
        ctx.mesh_transport.clone(),
        #[cfg(feature = "mesh")]
        ctx.serverless_manager.clone(),
        Arc::clone(&ctx.upstream_client_registry),
        ja4_hash.clone(),
    )
    .await?;

    let client_ip = flow.client_ip;
    let prepared = match flow.outcome {
        RequestPreparationOutcome::Continue(prepared) => *prepared,
        RequestPreparationOutcome::Respond(response) => {
            return Ok(response);
        }
    };

    let plugin_backend_arc: Option<Arc<dyn synvoid_http::WasmFilterBackend + Send + Sync>> = ctx
        .router
        .plugin_manager()
        .and_then(|pm| {
            let arc_any: Arc<dyn std::any::Any + Send + Sync> = Arc::clone(pm);
            arc_any.downcast::<crate::plugin::PluginManager>().ok()
        })
        .map(|arc| arc as Arc<dyn synvoid_http::WasmFilterBackend + Send + Sync>);
    let axum_router_lookup_arc: Option<
        Arc<dyn synvoid_http::AxumDynamicRouterLookup + Send + Sync>,
    > = ctx
        .router
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
            router: Arc::clone(&ctx.router),
            waf: Arc::clone(&ctx.waf),
            alt_svc: ctx.alt_svc.clone(),
            main_config: Arc::clone(&ctx.main_config),
            http_config: ctx.http_config.clone(),
            metrics: ctx.metrics.clone(),
            ipc: ctx.ipc.clone(),
            worker_id: ctx.worker_id,
            start,
            app_servers: ctx.app_servers.clone(),
            axum_router_lookup: axum_router_lookup_arc,
            plugin_backend: plugin_backend_arc,
            upstream_client_registry: Arc::clone(&ctx.upstream_client_registry),
            request_drop: Arc::clone(&request_drop),
            request_log: super::server::send_request_log_if_enabled,
            ja4_hash,
            forwarded_protocol,
            #[cfg(feature = "mesh")]
            serverless_manager: ctx.serverless_manager.clone(),
            #[cfg(feature = "mesh")]
            mesh_transport: ctx.mesh_transport.clone(),
            #[cfg(feature = "mesh")]
            mesh_backend_pool: ctx.mesh_backend_pool.clone(),
        },
        |method, url, headers, body, timeout| {
            let url = url.to_string();
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
