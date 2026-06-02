use bytes::Bytes;
use futures::Future;
use http::Response;
use http_body_util::combinators::BoxBody;
use std::collections::HashMap;
use std::convert::Infallible;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::config::site::SiteWebSocketConfig;
use crate::http::response_helpers::build_websocket_response;
use crate::router::{BackendType, RouteTarget};
use crate::waf::WafCore;

pub async fn maybe_handle_websocket_upgrade<AppServerFn, AppServerFut, TunnelFn, TunnelFut>(
    on_upgrade: Option<hyper::upgrade::OnUpgrade>,
    app_servers: &Option<Arc<RwLock<HashMap<String, Arc<crate::app_server::GranianSupervisor>>>>>,
    site_id: &str,
    target: &RouteTarget,
    path: &str,
    waf: &Arc<WafCore>,
    client_ip: IpAddr,
    headers: &http::HeaderMap,
    on_appserver: AppServerFn,
    on_tunnel: TunnelFn,
) -> Option<Result<Response<BoxBody<Bytes, Infallible>>, hyper::Error>>
where
    AppServerFn: FnOnce(
            hyper::upgrade::OnUpgrade,
            std::path::PathBuf,
            RouteTarget,
            String,
            Arc<WafCore>,
            IpAddr,
            SiteWebSocketConfig,
        ) -> AppServerFut
        + Send
        + 'static,
    AppServerFut: Future<Output = ()> + Send + 'static,
    TunnelFn: FnOnce(
            hyper::upgrade::OnUpgrade,
            RouteTarget,
            String,
            Arc<WafCore>,
            IpAddr,
            SiteWebSocketConfig,
        ) -> TunnelFut
        + Send
        + 'static,
    TunnelFut: Future<Output = ()> + Send + 'static,
{
    let upgraded = on_upgrade?;
    let ws_config = target.site_config.websocket.clone();
    let target_clone = target.clone();
    let path_clone = path.to_string();
    let waf_clone = waf.clone();

    tracing::info!(
        client_ip = %client_ip,
        path = %path_clone,
        upstream = %target_clone.upstream,
        "WebSocket upgrade request accepted"
    );

    if matches!(target.backend_type, BackendType::AppServer) {
        if let Some(servers) = app_servers {
            let servers_read = servers.read().await;
            if let Some(supervisor) = servers_read.get(site_id) {
                let socket_path = supervisor.config().resolve_socket_path();
                tokio::spawn(async move {
                    on_appserver(
                        upgraded,
                        socket_path,
                        target_clone,
                        path_clone,
                        waf_clone,
                        client_ip,
                        ws_config,
                    )
                    .await;
                });
                return Some(Ok(build_websocket_response(headers)));
            }
        }
    }

    tokio::spawn(async move {
        on_tunnel(
            upgraded,
            target_clone,
            path_clone,
            waf_clone,
            client_ip,
            ws_config,
        )
        .await;
    });

    Some(Ok(build_websocket_response(headers)))
}
