use std::collections::HashMap;
use std::convert::Infallible;
use std::future::Future;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Instant;

use bytes::Bytes;
use http::Response;
use http_body_util::combinators::BoxBody;
use tokio::sync::Mutex;
use tokio::sync::RwLock;

use synvoid_config::MainConfig;
use synvoid_metrics::bandwidth::EgressDirection;
use synvoid_metrics::WorkerMetrics;
use synvoid_proxy::client_registry::UpstreamClientRegistry;
use synvoid_proxy::{RouteTarget, Router};

use crate::app_server_backend_dispatch::maybe_handle_app_server_backend;
use crate::axum_dynamic_dispatch::maybe_handle_axum_dynamic_backend;
use crate::cgi_backend_dispatch::maybe_handle_cgi_backend;
use crate::fastcgi_php_backend_dispatch::maybe_handle_fastcgi_or_php_backend;
#[cfg(feature = "mesh")]
use crate::mesh_backend_dispatch::maybe_handle_mesh_backend;
#[cfg(feature = "mesh")]
use crate::serverless_backend_dispatch::maybe_handle_serverless_backend;
use crate::spin_backend_dispatch::maybe_handle_spin_backend;
use crate::static_backend_dispatch::maybe_handle_static_backend;
use crate::upstream_proxy_dispatch::handle_pass_upstream_proxy_phase;
use crate::upstream_proxy_dispatch_plan::prepare_upstream_proxy_dispatch_plan;
use crate::upload_validation_dispatch::{maybe_handle_upload_validation, UploadValidationWaf};
use crate::wasm_filter_dispatch::{
    maybe_handle_wasm_request_filter, WafErrorPageRenderer, WasmFilterBackend,
};
use crate::websocket_upgrade_dispatch::maybe_handle_websocket_upgrade;

pub trait BackendDispatchMetrics: Send + Sync {
    fn record_proxied(&self);
    fn record_upstream_success(&self);
    fn record_upstream_failure(&self);
    fn record_egress(&self, bytes: u64, direction: EgressDirection);
}

pub struct BackendDispatchContext<'a, W> {
    pub is_appserver: bool,
    pub appserver_socket_path: Option<PathBuf>,
    pub app_servers:
        &'a Option<Arc<RwLock<HashMap<String, Arc<synvoid_app_server::GranianSupervisor>>>>>,
    pub axum_router_lookup: Option<&'a dyn crate::AxumDynamicRouterLookup>,
    pub plugin_backend: Option<&'a dyn WasmFilterBackend>,
    pub target: &'a RouteTarget,
    pub site_id: &'a str,
    pub path: &'a str,
    pub waf: &'a Arc<W>,
    pub client_ip: IpAddr,
    pub router: &'a Arc<Router>,
    pub parts: &'a http::request::Parts,
    pub method: &'a http::Method,
    pub full_body_arc: &'a Arc<Bytes>,
    pub ipc: Option<Arc<Mutex<synvoid_ipc::AsyncIpcStream>>>,
    pub worker_id: Option<synvoid_ipc::WorkerId>,
    pub main_config: &'a Arc<MainConfig>,
    pub method_str: &'a str,
    pub start: Instant,
    pub user_agent: Option<&'a str>,
    pub alt_svc: &'a Option<String>,
    pub req_metrics: Option<&'a dyn BackendDispatchMetrics>,
    pub metrics: &'a Option<Arc<WorkerMetrics>>,
    pub request_body_size: u64,
    pub body_slice: &'a Option<Arc<Bytes>>,
    pub upstream_client_registry: &'a Arc<UpstreamClientRegistry>,
    pub client: &'a synvoid_http_client::HttpClient,
    #[cfg(feature = "mesh")]
    pub serverless_manager: &'a Option<Arc<synvoid_serverless::ServerlessManager>>,
    #[cfg(feature = "mesh")]
    pub mesh_transport: &'a Option<Arc<synvoid_mesh::mesh::transports::MeshTransportManager>>,
    #[cfg(feature = "mesh")]
    pub mesh_backend_pool: &'a Option<Arc<synvoid_mesh::mesh::MeshBackendPool>>,
}

#[allow(clippy::too_many_arguments)]
pub async fn handle_pass_backend_dispatch<W, OnLogFn, QuicTunnelFn, PoisonFn, PoisonFut>(
    on_upgrade: Option<hyper::upgrade::OnUpgrade>,
    dispatch_ctx: BackendDispatchContext<'_, W>,
    on_request_log: OnLogFn,
    quictunnel_request: QuicTunnelFn,
    poison_image: PoisonFn,
) -> Result<Response<BoxBody<Bytes, Infallible>>, hyper::Error>
where
    W: synvoid_proxy::protocol::trait_def::WafCoreBackend
        + UploadValidationWaf
        + WafErrorPageRenderer
        + Send
        + Sync
        + 'static,
    OnLogFn: Fn(
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
    ) + Clone,
    QuicTunnelFn: Fn(
        http::Method,
        &str,
        Option<&http::HeaderMap>,
        Option<Bytes>,
        Option<std::time::Duration>,
    ) -> futures::future::BoxFuture<'static, anyhow::Result<synvoid_http_client::HttpResponse>>,
    PoisonFn: Fn(
        Bytes,
        String,
        Option<String>,
        Option<synvoid_config::site::SiteImagePoisonConfig>,
    ) -> PoisonFut + Clone,
    PoisonFut: Future<Output = Bytes>,
{
    let waf = Arc::clone(dispatch_ctx.waf);

    if let Some(rm) = dispatch_ctx.req_metrics {
        rm.record_proxied();
    }

    if let Some(response) = maybe_handle_websocket_upgrade(
        on_upgrade,
        dispatch_ctx.is_appserver,
        dispatch_ctx.appserver_socket_path.clone(),
        dispatch_ctx.target.clone(),
        &dispatch_ctx.target.upstream,
        dispatch_ctx.path,
        &waf,
        dispatch_ctx.client_ip,
        &dispatch_ctx.parts.headers,
        dispatch_ctx.target.site_config.websocket.clone(),
        |upgraded, socket_path, target, path, waf, client_ip, ws_config| async move {
            let waf: Arc<dyn synvoid_proxy::protocol::trait_def::WafCoreBackend> = waf;
            crate::handle_websocket_to_appserver(
                upgraded,
                socket_path,
                target,
                path,
                waf,
                client_ip,
                ws_config,
            )
            .await
        },
        |upgraded, target, path, waf, client_ip, ws_config| async move {
            let waf: Arc<dyn synvoid_proxy::protocol::trait_def::WafCoreBackend> = waf;
            crate::handle_websocket_tunnel(upgraded, target, path, waf, client_ip, ws_config).await
        },
    )
    .await
    {
        return response;
    }

    if let Some(resp) = maybe_handle_axum_dynamic_backend(
        dispatch_ctx.axum_router_lookup,
        dispatch_ctx.target,
        dispatch_ctx.site_id,
        dispatch_ctx.path,
        dispatch_ctx.parts,
        dispatch_ctx.alt_svc,
        dispatch_ctx.main_config,
    )
    .await
    {
        return Ok(resp);
    }

    if let Some(resp) = maybe_handle_static_backend(
        dispatch_ctx.target,
        dispatch_ctx.path,
        dispatch_ctx.method,
        &dispatch_ctx.parts.headers,
    )
    .await
    {
        return Ok(resp);
    }

    #[cfg(feature = "mesh")]
    if dispatch_ctx.is_appserver {
        if let Some(response) = maybe_handle_app_server_backend(
            dispatch_ctx.app_servers,
            dispatch_ctx.target,
            dispatch_ctx.site_id,
            dispatch_ctx.path,
            dispatch_ctx.method,
            dispatch_ctx.parts,
            dispatch_ctx.full_body_arc,
            dispatch_ctx.alt_svc,
            dispatch_ctx.main_config,
        )
        .await
        {
            return Ok(response);
        }
    }

    if matches!(
        dispatch_ctx.target.backend_type,
        synvoid_proxy::BackendType::Serverless
    ) {
        #[cfg(feature = "mesh")]
        if let Some(response) = maybe_handle_serverless_backend(
            dispatch_ctx.serverless_manager,
            dispatch_ctx.mesh_transport,
            dispatch_ctx.method,
            dispatch_ctx.path,
            dispatch_ctx.parts,
            dispatch_ctx.full_body_arc,
            dispatch_ctx.ipc.clone(),
            dispatch_ctx.worker_id,
            dispatch_ctx.main_config,
            dispatch_ctx.client_ip,
            dispatch_ctx.method_str,
            dispatch_ctx.start,
            dispatch_ctx.site_id,
            dispatch_ctx.user_agent,
            dispatch_ctx.alt_svc,
            on_request_log.clone(),
        )
        .await
        {
            return response;
        }
    }

    if let Some(response) = maybe_handle_spin_backend(
        dispatch_ctx.target,
        dispatch_ctx.site_id,
        dispatch_ctx.path,
        dispatch_ctx.parts,
        dispatch_ctx.full_body_arc,
        dispatch_ctx.ipc.clone(),
        dispatch_ctx.worker_id,
        dispatch_ctx.main_config,
        dispatch_ctx.client_ip,
        dispatch_ctx.method_str,
        dispatch_ctx.start,
        dispatch_ctx.user_agent,
        dispatch_ctx.alt_svc,
        on_request_log.clone(),
    )
    .await
    {
        return Ok(response);
    }

    if let Some(response) = maybe_handle_fastcgi_or_php_backend(
        dispatch_ctx.target,
        dispatch_ctx.router,
        dispatch_ctx.site_id,
        dispatch_ctx.path,
        dispatch_ctx.method,
        dispatch_ctx.parts,
        dispatch_ctx.full_body_arc,
        dispatch_ctx.alt_svc,
        dispatch_ctx.main_config,
        |status, message| waf.as_ref().render_page(status, message),
        poison_image.clone(),
    )
    .await
    {
        return Ok(response);
    }

    if let Some(response) = maybe_handle_cgi_backend(
        dispatch_ctx.target,
        dispatch_ctx.site_id,
        dispatch_ctx.path,
        dispatch_ctx.method,
        dispatch_ctx.parts,
        dispatch_ctx.full_body_arc,
        dispatch_ctx.client_ip,
        dispatch_ctx.alt_svc,
        dispatch_ctx.main_config,
        |status, message| waf.as_ref().render_page(status, message),
    )
    .await
    {
        return Ok(response);
    }

    if let Some(response) = maybe_handle_app_server_backend(
        dispatch_ctx.app_servers,
        dispatch_ctx.target,
        dispatch_ctx.site_id,
        dispatch_ctx.path,
        dispatch_ctx.method,
        dispatch_ctx.parts,
        dispatch_ctx.full_body_arc,
        dispatch_ctx.alt_svc,
        dispatch_ctx.main_config,
    )
    .await
    {
        return Ok(response);
    }

    #[cfg(feature = "mesh")]
    if let Some(response) = maybe_handle_mesh_backend(
        dispatch_ctx.mesh_backend_pool,
        dispatch_ctx.target,
        dispatch_ctx.site_id,
        dispatch_ctx.path,
        dispatch_ctx.parts,
        dispatch_ctx.full_body_arc,
        dispatch_ctx.main_config,
        dispatch_ctx.alt_svc,
        dispatch_ctx.metrics,
        dispatch_ctx.request_body_size,
        || {
            if let Some(rm) = dispatch_ctx.req_metrics {
                rm.record_upstream_success();
            }
        },
        || {
            if let Some(rm) = dispatch_ctx.req_metrics {
                rm.record_upstream_failure();
            }
        },
    )
    .await
    {
        return response;
    }

    if let Some(response) = maybe_handle_wasm_request_filter(
        dispatch_ctx.plugin_backend,
        dispatch_ctx.target,
        dispatch_ctx.path,
        dispatch_ctx.method,
        dispatch_ctx.parts,
        dispatch_ctx.body_slice,
        dispatch_ctx.client_ip,
        waf.as_ref(),
        dispatch_ctx.alt_svc,
        dispatch_ctx.main_config,
        |status| {
            on_request_log(
                dispatch_ctx.ipc.clone(),
                dispatch_ctx.worker_id,
                dispatch_ctx.main_config,
                dispatch_ctx.client_ip,
                dispatch_ctx.method_str,
                dispatch_ctx.path,
                status,
                dispatch_ctx.start.elapsed().as_millis() as u64,
                dispatch_ctx.site_id,
                dispatch_ctx.user_agent,
                false,
            );
        },
    ) {
        return Ok(response);
    }

    let content_type = dispatch_ctx
        .parts
        .headers
        .get("content-type")
        .and_then(|v| v.to_str().ok());
    if let Some(response) = maybe_handle_upload_validation(
        &waf,
        &dispatch_ctx.target.site_id,
        dispatch_ctx.path,
        dispatch_ctx.client_ip,
        dispatch_ctx.full_body_arc,
        dispatch_ctx.alt_svc,
        dispatch_ctx.main_config,
        content_type,
    )
    .await
    {
        return Ok(response);
    }

    let dispatch_plan = prepare_upstream_proxy_dispatch_plan(
        dispatch_ctx.target,
        dispatch_ctx.path,
        dispatch_ctx.main_config,
        dispatch_ctx.full_body_arc.len() as u64,
        dispatch_ctx.client_ip,
        dispatch_ctx.parts,
        dispatch_ctx.upstream_client_registry,
        dispatch_ctx.client,
    );

    handle_pass_upstream_proxy_phase(
        dispatch_ctx.target,
        dispatch_ctx.router,
        dispatch_ctx.path,
        dispatch_ctx.site_id,
        dispatch_ctx.method,
        dispatch_ctx.parts,
        dispatch_ctx.full_body_arc,
        dispatch_plan,
        dispatch_ctx.alt_svc,
        dispatch_ctx.main_config,
        dispatch_ctx.metrics,
        dispatch_ctx.request_body_size,
        #[cfg(feature = "mesh")]
        dispatch_ctx.mesh_transport,
        quictunnel_request,
        || {
            if let Some(rm) = dispatch_ctx.req_metrics {
                rm.record_upstream_success();
            }
        },
        || {
            if let Some(rm) = dispatch_ctx.req_metrics {
                rm.record_upstream_failure();
            }
        },
        |egress_len| {
            if let Some(rm) = dispatch_ctx.req_metrics {
                rm.record_egress(egress_len, EgressDirection::Error);
            }
        },
        poison_image,
    )
    .await
}
