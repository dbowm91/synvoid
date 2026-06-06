use bytes::Bytes;
use http::Response;
use http_body_util::combinators::BoxBody;
use std::convert::Infallible;
use std::future::Future;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;

use synvoid_config::site::SiteWebSocketConfig;

use crate::response_helpers::build_websocket_response;

pub async fn maybe_handle_websocket_upgrade<
    TTarget,
    WafT,
    AppServerFn,
    AppServerFut,
    TunnelFn,
    TunnelFut,
>(
    on_upgrade: Option<hyper::upgrade::OnUpgrade>,
    is_appserver: bool,
    appserver_socket_path: Option<PathBuf>,
    target: TTarget,
    upstream: &str,
    path: &str,
    waf: &Arc<WafT>,
    client_ip: IpAddr,
    headers: &http::HeaderMap,
    ws_config: SiteWebSocketConfig,
    on_appserver: AppServerFn,
    on_tunnel: TunnelFn,
) -> Option<Result<Response<BoxBody<Bytes, Infallible>>, hyper::Error>>
where
    TTarget: Clone + Send + 'static,
    WafT: Send + Sync + 'static,
    AppServerFn: FnOnce(
            hyper::upgrade::OnUpgrade,
            PathBuf,
            TTarget,
            String,
            Arc<WafT>,
            IpAddr,
            SiteWebSocketConfig,
        ) -> AppServerFut
        + Send
        + 'static,
    AppServerFut: Future<Output = ()> + Send + 'static,
    TunnelFn: FnOnce(
            hyper::upgrade::OnUpgrade,
            TTarget,
            String,
            Arc<WafT>,
            IpAddr,
            SiteWebSocketConfig,
        ) -> TunnelFut
        + Send
        + 'static,
    TunnelFut: Future<Output = ()> + Send + 'static,
{
    let upgraded = on_upgrade?;
    let target_clone = target.clone();
    let path_clone = path.to_string();
    let waf_clone = waf.clone();

    tracing::info!(
        client_ip = %client_ip,
        path = %path_clone,
        upstream = %upstream,
        "WebSocket upgrade request accepted"
    );

    if is_appserver {
        if let Some(socket_path) = appserver_socket_path {
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
