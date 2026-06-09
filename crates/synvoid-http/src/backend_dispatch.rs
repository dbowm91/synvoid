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
use crate::upload_validation_dispatch::{maybe_handle_upload_validation, UploadValidationWaf};
use crate::upstream_proxy_dispatch::handle_pass_upstream_proxy_phase;
use crate::upstream_proxy_dispatch_plan::prepare_upstream_proxy_dispatch_plan;
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

pub struct BackendDispatchContext<W> {
    pub is_appserver: bool,
    pub appserver_socket_path: Option<PathBuf>,
    pub app_servers:
        Option<Arc<RwLock<HashMap<String, Arc<synvoid_app_server::GranianSupervisor>>>>>,
    pub axum_router_lookup: Option<Arc<dyn crate::AxumDynamicRouterLookup + Send + Sync>>,
    pub plugin_backend: Option<Arc<dyn WasmFilterBackend + Send + Sync>>,
    pub target: RouteTarget,
    pub site_id: String,
    pub path: String,
    pub waf: Arc<W>,
    pub client_ip: IpAddr,
    pub router: Arc<Router>,
    pub parts: http::request::Parts,
    pub method: http::Method,
    pub full_body_arc: Arc<Bytes>,
    pub ipc: Option<Arc<Mutex<synvoid_ipc::AsyncIpcStream>>>,
    pub worker_id: Option<synvoid_ipc::WorkerId>,
    pub main_config: Arc<MainConfig>,
    pub method_str: String,
    pub start: Instant,
    pub user_agent: Option<String>,
    pub alt_svc: Option<String>,
    pub req_metrics: Option<Arc<dyn BackendDispatchMetrics>>,
    pub metrics: Option<Arc<WorkerMetrics>>,
    pub request_body_size: u64,
    pub body_slice: Option<Arc<Bytes>>,
    pub upstream_client_registry: Arc<UpstreamClientRegistry>,
    pub client: synvoid_http_client::HttpClient,
    #[cfg(feature = "mesh")]
    pub serverless_manager: Option<Arc<synvoid_serverless::ServerlessManager>>,
    #[cfg(feature = "mesh")]
    pub mesh_transport: Option<Arc<synvoid_mesh::mesh::transports::MeshTransportManager>>,
    #[cfg(feature = "mesh")]
    pub mesh_backend_pool: Option<Arc<synvoid_mesh::mesh::MeshBackendPool>>,
}

#[allow(clippy::too_many_arguments)]
pub async fn handle_pass_backend_dispatch<
    W,
    OnLogFn,
    QuicTunnelFn,
    MarkImageRightsFn,
    MarkImageRightsFut,
>(
    on_upgrade: Option<hyper::upgrade::OnUpgrade>,
    dispatch_ctx: BackendDispatchContext<W>,
    on_request_log: OnLogFn,
    quictunnel_request: QuicTunnelFn,
    mark_image_rights: MarkImageRightsFn,
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
        ) + Clone
        + Send
        + Sync
        + 'static,
    QuicTunnelFn: Fn(
            http::Method,
            &str,
            Option<http::HeaderMap>,
            Option<Bytes>,
            Option<std::time::Duration>,
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
    MarkImageRightsFut: Future<Output = Bytes> + Send + 'static,
{
    let BackendDispatchContext {
        is_appserver,
        appserver_socket_path,
        app_servers,
        axum_router_lookup,
        plugin_backend,
        target,
        site_id,
        path,
        waf,
        client_ip,
        router,
        parts,
        method,
        full_body_arc,
        ipc,
        worker_id,
        main_config,
        method_str,
        start,
        user_agent,
        alt_svc,
        req_metrics,
        metrics,
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
    } = dispatch_ctx;

    let req_metrics = req_metrics;

    if let Some(rm) = req_metrics.clone() {
        rm.record_proxied();
    }

    if let Some(response) = maybe_handle_websocket_upgrade(
        on_upgrade,
        is_appserver,
        appserver_socket_path.clone(),
        target.clone(),
        target.upstream.to_string(),
        path.clone(),
        waf.clone(),
        client_ip,
        parts.headers.clone(),
        target.site_config.websocket.clone(),
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
        axum_router_lookup.clone(),
        target.clone(),
        site_id.clone(),
        path.clone(),
        parts.clone(),
        alt_svc.clone(),
        Arc::clone(&main_config),
    )
    .await
    {
        return Ok(resp);
    }

    if let Some(resp) = maybe_handle_static_backend(
        target.clone(),
        path.clone(),
        method.clone(),
        parts.headers.clone(),
    )
    .await
    {
        return Ok(resp);
    }

    #[cfg(feature = "mesh")]
    if is_appserver {
        if let Some(response) = maybe_handle_app_server_backend(
            app_servers.clone(),
            target.clone(),
            site_id.clone(),
            path.clone(),
            method.clone(),
            parts.clone(),
            full_body_arc.clone(),
            alt_svc.clone(),
            Arc::clone(&main_config),
        )
        .await
        {
            return Ok(response);
        }
    }

    if matches!(target.backend_type, synvoid_proxy::BackendType::Serverless) {
        #[cfg(feature = "mesh")]
        if let Some(response) = maybe_handle_serverless_backend(
            &serverless_manager,
            &mesh_transport,
            &method,
            &path,
            &parts,
            &full_body_arc,
            ipc.clone(),
            worker_id,
            &main_config,
            client_ip,
            &method_str,
            start,
            &site_id,
            user_agent.as_deref(),
            &alt_svc,
            on_request_log.clone(),
        )
        .await
        {
            return response;
        }
    }

    if let Some(response) = maybe_handle_spin_backend(
        target.clone(),
        site_id.clone(),
        path.clone(),
        parts.clone(),
        full_body_arc.clone(),
        ipc.clone(),
        worker_id,
        Arc::clone(&main_config),
        client_ip,
        method_str.clone(),
        start,
        user_agent.clone(),
        alt_svc.clone(),
        on_request_log.clone(),
    )
    .await
    {
        return Ok(response);
    }

    if let Some(response) = maybe_handle_fastcgi_or_php_backend(
        target.clone(),
        Arc::clone(&router),
        site_id.clone(),
        path.clone(),
        method.clone(),
        parts.clone(),
        full_body_arc.clone(),
        alt_svc.clone(),
        Arc::clone(&main_config),
        {
            let waf = Arc::clone(&waf);
            move |status, message| waf.as_ref().render_page(status, message)
        },
        mark_image_rights.clone(),
    )
    .await
    {
        return Ok(response);
    }

    if let Some(response) = maybe_handle_cgi_backend(
        target.clone(),
        site_id.clone(),
        path.clone(),
        method.clone(),
        parts.clone(),
        full_body_arc.clone(),
        client_ip,
        alt_svc.clone(),
        Arc::clone(&main_config),
        {
            let waf = Arc::clone(&waf);
            move |status, message| waf.as_ref().render_page(status, message)
        },
    )
    .await
    {
        return Ok(response);
    }

    if let Some(response) = maybe_handle_app_server_backend(
        app_servers.clone(),
        target.clone(),
        site_id.clone(),
        path.clone(),
        method.clone(),
        parts.clone(),
        full_body_arc.clone(),
        alt_svc.clone(),
        Arc::clone(&main_config),
    )
    .await
    {
        return Ok(response);
    }

    #[cfg(feature = "mesh")]
    if let Some(response) = maybe_handle_mesh_backend(
        &mesh_backend_pool,
        &target,
        &site_id,
        &path,
        &parts,
        &full_body_arc,
        &main_config,
        &alt_svc,
        &metrics,
        request_body_size,
        {
            let req_metrics = req_metrics.clone();
            move || {
                if let Some(rm) = req_metrics.clone() {
                    rm.record_upstream_success();
                }
            }
        },
        {
            let req_metrics = req_metrics.clone();
            move || {
                if let Some(rm) = req_metrics.clone() {
                    rm.record_upstream_failure();
                }
            }
        },
    )
    .await
    {
        return response;
    }

    if let Some(response) = maybe_handle_wasm_request_filter(
        plugin_backend.as_deref(),
        &target,
        &path,
        &method,
        &parts,
        &body_slice,
        client_ip,
        waf.as_ref(),
        &alt_svc,
        &main_config,
        |status| {
            on_request_log(
                ipc.clone(),
                worker_id,
                &main_config,
                client_ip,
                &method_str,
                &path,
                status,
                start.elapsed().as_millis() as u64,
                &site_id,
                user_agent.as_deref(),
                false,
            );
        },
    ) {
        return Ok(response);
    }

    let content_type = parts
        .headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string());
    if let Some(response) = maybe_handle_upload_validation(
        Arc::clone(&waf),
        target.site_id.to_string(),
        path.clone(),
        client_ip,
        full_body_arc.clone(),
        alt_svc.clone(),
        Arc::clone(&main_config),
        content_type,
    )
    .await
    {
        return Ok(response);
    }

    let dispatch_plan = prepare_upstream_proxy_dispatch_plan(
        &target,
        &path,
        &main_config,
        full_body_arc.len() as u64,
        client_ip,
        &parts,
        &upstream_client_registry,
        &client,
    );

    handle_pass_upstream_proxy_phase(
        target,
        router,
        path,
        site_id,
        method,
        parts,
        full_body_arc,
        dispatch_plan,
        alt_svc,
        main_config,
        metrics,
        request_body_size,
        #[cfg(feature = "mesh")]
        mesh_transport,
        quictunnel_request,
        {
            let req_metrics = req_metrics.clone();
            move || {
                if let Some(rm) = req_metrics.clone() {
                    rm.record_upstream_success();
                }
            }
        },
        {
            let req_metrics = req_metrics.clone();
            move || {
                if let Some(rm) = req_metrics.clone() {
                    rm.record_upstream_failure();
                }
            }
        },
        {
            let req_metrics = req_metrics.clone();
            move |egress_len| {
                if let Some(rm) = req_metrics.clone() {
                    rm.record_egress(egress_len, EgressDirection::Error);
                }
            }
        },
        mark_image_rights,
    )
    .await
}
