use futures::Future;
use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Arc;
use tokio::sync::RwLock;

use crate::config::site::SiteWebSocketConfig;
use crate::router::{BackendType, RouteTarget};
use crate::waf::WafCore;

use synvoid_http::maybe_handle_websocket_upgrade as maybe_handle_websocket_upgrade_impl;

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
) -> Option<Result<synvoid_http::BoxBodyResponse, hyper::Error>>
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
    let is_appserver = matches!(target.backend_type, BackendType::AppServer);
    let appserver_socket_path = if is_appserver {
        if let Some(servers) = app_servers.clone() {
            let servers_read = servers.read().await;
            servers_read
                .get(site_id)
                .map(|supervisor| supervisor.config().resolve_socket_path())
        } else {
            None
        }
    } else {
        None
    };

    maybe_handle_websocket_upgrade_impl(
        on_upgrade,
        is_appserver,
        appserver_socket_path,
        target.clone(),
        target.upstream.to_string(),
        path.to_string(),
        Arc::clone(waf),
        client_ip,
        headers.clone(),
        target.site_config.websocket.clone(),
        on_appserver,
        on_tunnel,
    )
    .await
}
