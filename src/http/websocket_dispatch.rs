use std::sync::Arc;

use crate::config::site::SiteWebSocketConfig;
use crate::router::RouteTarget;
use crate::waf::WafCore;

use synvoid_http::{
    handle_websocket_to_appserver as handle_websocket_to_appserver_impl,
    handle_websocket_tunnel as handle_websocket_tunnel_impl,
};

pub async fn handle_websocket_tunnel(
    upgraded: hyper::upgrade::OnUpgrade,
    target: RouteTarget,
    path: String,
    waf: Arc<WafCore>,
    client_ip: std::net::IpAddr,
    ws_config: SiteWebSocketConfig,
) {
    let waf: Arc<dyn synvoid_proxy::protocol::trait_def::WafCoreBackend> = waf;
    handle_websocket_tunnel_impl(upgraded, target, path, waf, client_ip, ws_config).await
}

pub async fn handle_websocket_to_appserver(
    upgraded: hyper::upgrade::OnUpgrade,
    socket_path: std::path::PathBuf,
    target: RouteTarget,
    path: String,
    waf: Arc<WafCore>,
    client_ip: std::net::IpAddr,
    ws_config: SiteWebSocketConfig,
) {
    let waf: Arc<dyn synvoid_proxy::protocol::trait_def::WafCoreBackend> = waf;
    handle_websocket_to_appserver_impl(
        upgraded,
        socket_path,
        target,
        path,
        waf,
        client_ip,
        ws_config,
    )
    .await
}
