use bytes::Bytes;
use http::Response;
use http_body_util::combinators::BoxBody;
use http_body_util::BodyExt;
use std::convert::Infallible;
use std::future::Future;
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::Arc;

use synvoid_config::site::SiteWebSocketConfig;

use crate::inbound::{BoxTunnelIo, TunnelFuture, UpgradeCapability, UpgradeHandshake};
use crate::response_helpers::build_websocket_response;

fn accept_failed_response() -> Response<BoxBody<Bytes, Infallible>> {
    // Unreachable with the computed handshake headers below (the capability
    // only rejects application framing control); fail closed without
    // falling through to ordinary dispatch.
    Response::builder()
        .status(500)
        .body(http_body_util::Full::new(Bytes::from_static(b"Internal Server Error")).boxed())
        .unwrap_or_else(|_| crate::fallback_error_boxed())
}

fn handshake_response_from(handshake: UpgradeHandshake) -> Response<BoxBody<Bytes, Infallible>> {
    let mut builder = Response::builder().status(handshake.status);
    for (name, value) in handshake.headers.iter() {
        builder = builder.header(name, value);
    }
    builder
        .body(http_body_util::Full::new(Bytes::new()).boxed())
        .unwrap_or_else(|_| crate::fallback_error_boxed())
}

#[allow(clippy::too_many_arguments)]
pub async fn maybe_handle_websocket_upgrade<
    TTarget,
    WafT,
    AppServerFn,
    AppServerFut,
    TunnelFn,
    TunnelFut,
>(
    upgrade: Option<Box<dyn UpgradeCapability>>,
    is_appserver: bool,
    appserver_socket_path: Option<PathBuf>,
    target: TTarget,
    upstream: String,
    path: String,
    waf: Arc<WafT>,
    client_ip: IpAddr,
    headers: http::HeaderMap,
    ws_config: SiteWebSocketConfig,
    on_appserver: AppServerFn,
    on_tunnel: TunnelFn,
) -> Option<Result<Response<BoxBody<Bytes, Infallible>>, hyper::Error>>
where
    TTarget: Clone + Send + 'static,
    WafT: Send + Sync + 'static,
    AppServerFn: FnOnce(
            BoxTunnelIo,
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
    TunnelFn: FnOnce(BoxTunnelIo, TTarget, String, Arc<WafT>, IpAddr, SiteWebSocketConfig) -> TunnelFut
        + Send
        + 'static,
    TunnelFut: Future<Output = ()> + Send + 'static,
{
    let capability = upgrade?;
    let target_clone = target.clone();
    let waf_clone = Arc::clone(&waf);

    tracing::info!(
        client_ip = %client_ip,
        path = %path,
        upstream = %upstream,
        protocol = capability.request().protocol,
        "WebSocket upgrade request accepted"
    );

    // The 101 description is computed exactly as before; the capability
    // validates it (no application framing control) and stages the
    // transport handoff for the handler.
    let accept_headers = build_websocket_response(&headers).into_parts().0.headers;

    if is_appserver {
        if let Some(socket_path) = appserver_socket_path {
            let path_clone = path.clone();
            let handshake = match capability.accept(
                accept_headers,
                Box::new(move |io| {
                    Box::pin(async move {
                        on_appserver(
                            io,
                            socket_path,
                            target_clone,
                            path_clone,
                            waf_clone,
                            client_ip,
                            ws_config,
                        )
                        .await;
                    }) as TunnelFuture
                }),
            ) {
                Ok(handshake) => handshake,
                Err(e) => {
                    tracing::error!("WebSocket upgrade accept failed: {}", e);
                    return Some(Ok(accept_failed_response()));
                }
            };
            return Some(Ok(handshake_response_from(handshake)));
        }
    }

    let handshake = match capability.accept(
        accept_headers,
        Box::new(move |io| {
            Box::pin(async move {
                on_tunnel(io, target_clone, path, waf_clone, client_ip, ws_config).await;
            }) as TunnelFuture
        }),
    ) {
        Ok(handshake) => handshake,
        Err(e) => {
            tracing::error!("WebSocket upgrade accept failed: {}", e);
            return Some(Ok(accept_failed_response()));
        }
    };

    Some(Ok(handshake_response_from(handshake)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::inbound::{UpgradeError, UpgradeRequest};

    /// Deterministic test capability: records acceptance, never touches a
    /// transport.
    struct TestCapability {
        request: UpgradeRequest,
        accepted: std::sync::Arc<std::sync::atomic::AtomicBool>,
    }

    impl UpgradeCapability for TestCapability {
        fn request(&self) -> &UpgradeRequest {
            &self.request
        }

        fn accept(
            self: Box<Self>,
            headers: http::HeaderMap,
            handler: crate::inbound::TunnelHandler,
        ) -> Result<UpgradeHandshake, UpgradeError> {
            if headers.contains_key("content-length") {
                return Err(UpgradeError::ForbiddenHeader("content-length".to_string()));
            }
            self.accepted
                .store(true, std::sync::atomic::Ordering::SeqCst);
            drop(handler);
            Ok(UpgradeHandshake {
                status: http::StatusCode::SWITCHING_PROTOCOLS,
                headers,
            })
        }
    }

    fn ws_headers() -> http::HeaderMap {
        let mut headers = http::HeaderMap::new();
        headers.insert(
            "sec-websocket-key",
            "dGhlIHNhbXBsZSBub25jZQ==".parse().unwrap(),
        );
        headers.insert("sec-websocket-protocol", "chat".parse().unwrap());
        headers
    }

    #[tokio::test]
    async fn neutral_accept_returns_101_with_negotiated_headers() {
        let accepted = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let capability: Box<dyn UpgradeCapability> = Box::new(TestCapability {
            request: UpgradeRequest::websocket(),
            accepted: accepted.clone(),
        });
        let out = maybe_handle_websocket_upgrade(
            Some(capability),
            false,
            None,
            (),
            "upstream".to_string(),
            "/ws".to_string(),
            Arc::new(()),
            "127.0.0.1".parse().unwrap(),
            ws_headers(),
            SiteWebSocketConfig::default(),
            |_io: BoxTunnelIo,
             _path: PathBuf,
             _t: (),
             _p: String,
             _w: Arc<()>,
             _ip: IpAddr,
             _c: SiteWebSocketConfig| async move {},
            |_io: BoxTunnelIo,
             _t: (),
             _p: String,
             _w: Arc<()>,
             _ip: IpAddr,
             _c: SiteWebSocketConfig| async move {},
        )
        .await
        .expect("upgrade handled")
        .expect("no transport error");
        assert_eq!(out.status(), 101);
        assert!(accepted.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(out.headers().get("sec-websocket-protocol").unwrap(), "chat");
        assert!(out.headers().get("sec-websocket-accept").is_some());
    }

    #[tokio::test]
    async fn neutral_decline_stays_unhandled() {
        let out = maybe_handle_websocket_upgrade(
            None,
            false,
            None,
            (),
            "upstream".to_string(),
            "/ws".to_string(),
            Arc::new(()),
            "127.0.0.1".parse().unwrap(),
            ws_headers(),
            SiteWebSocketConfig::default(),
            |_io: BoxTunnelIo,
             _path: PathBuf,
             _t: (),
             _p: String,
             _w: Arc<()>,
             _ip: IpAddr,
             _c: SiteWebSocketConfig| async move {},
            |_io: BoxTunnelIo,
             _t: (),
             _p: String,
             _w: Arc<()>,
             _ip: IpAddr,
             _c: SiteWebSocketConfig| async move {},
        )
        .await;
        assert!(out.is_none());
    }
}
