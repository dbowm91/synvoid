use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;

use futures::{SinkExt, StreamExt};
use hyper_util::rt::TokioIo;
use metrics::counter;
use tokio_tungstenite::tungstenite::protocol::Role;
use tokio_tungstenite::{connect_async, WebSocketStream};

use crate::config::site::SiteWebSocketConfig;
use crate::protocol::trait_def::{ProtocolHandler, WafAction, WafCoreBackend};
use crate::protocol::types::{ProtocolRequest, ProtocolType};
use crate::protocol::websocket::WebSocketHandler;
use crate::proxy::join_upstream_url;
use crate::waf::WafCore;
use crate::RunningFlag;

pub async fn handle_websocket_tunnel(
    upgraded: hyper::upgrade::OnUpgrade,
    target: crate::router::RouteTarget,
    path: String,
    waf: Arc<WafCore>,
    client_ip: std::net::IpAddr,
    ws_config: SiteWebSocketConfig,
) {
    let upgraded = match upgraded.await {
        Ok(up) => up,
        Err(e) => {
            tracing::error!("WebSocket upgrade failed: {}", e);
            counter!("synvoid.websocket.upgrade_failed").increment(1);
            return;
        }
    };

    counter!("synvoid.websocket.connections").increment(1);

    let ws_stream =
        WebSocketStream::from_raw_socket(TokioIo::new(upgraded), Role::Server, None).await;

    let (mut client_tx, mut client_rx) = ws_stream.split();

    let ws_handler = WebSocketHandler::new()
        .with_max_message_size(ws_config.max_message_size.unwrap_or(16 * 1024 * 1024))
        .with_mask_required(ws_config.mask_required.unwrap_or(false));

    let ws_upstream = target
        .upstream
        .replacen("https://", "wss://", 1)
        .replacen("http://", "ws://", 1);
    let upstream_url = join_upstream_url(&ws_upstream, &path);

    tracing::debug!(url = %upstream_url, "Connecting to upstream WebSocket");

    let (upstream_ws, _) = match connect_async(&upstream_url).await {
        Ok(ws) => ws,
        Err(e) => {
            tracing::error!("Failed to connect to upstream WebSocket: {}", e);
            counter!("synvoid.websocket.upstream_failed").increment(1);
            return;
        }
    };

    counter!("synvoid.websocket.upstream_connected").increment(1);

    let (mut upstream_tx, mut upstream_rx) = upstream_ws.split();

    let path_clone = path.clone();
    let waf_clone = waf.clone();
    let should_close = std::sync::Arc::new(RunningFlag::new());
    let should_close_clone = should_close.clone();

    let client_to_upstream = async {
        while let Some(msg_result) = client_rx.next().await {
            if !should_close_clone.is_running() {
                break;
            }

            let msg = match msg_result {
                Ok(m) => m,
                Err(e) => {
                    tracing::debug!("WebSocket client error: {}", e);
                    break;
                }
            };

            let (method, body_vec) = match &msg {
                tokio_tungstenite::tungstenite::Message::Text(t) => ("TEXT", t.as_bytes().to_vec()),
                tokio_tungstenite::tungstenite::Message::Binary(b) => ("BINARY", b.to_vec()),
                tokio_tungstenite::tungstenite::Message::Close(_) => {
                    let _ = upstream_tx
                        .send(tokio_tungstenite::tungstenite::Message::Close(None))
                        .await;
                    break;
                }
                tokio_tungstenite::tungstenite::Message::Ping(data) => {
                    let _ = upstream_tx
                        .send(tokio_tungstenite::tungstenite::Message::Pong(data.clone()))
                        .await;
                    continue;
                }
                tokio_tungstenite::tungstenite::Message::Pong(_) => continue,
                tokio_tungstenite::tungstenite::Message::Frame(_) => continue,
            };

            let mut proto_request = ProtocolRequest {
                client_ip: SocketAddr::from((client_ip, 0)),
                method: method.to_string(),
                path: path_clone.clone(),
                headers: HashMap::new(),
                body: body_vec,
                protocol: ProtocolType::WebSocket,
                metadata: HashMap::new(),
            };

            let action = ws_handler.apply_waf(&mut proto_request, &(waf_clone.clone() as Arc<dyn WafCoreBackend>));
            match action {
                WafAction::Block => {
                    tracing::warn!(
                        client_ip = %client_ip,
                        "WebSocket message blocked by WAF"
                    );
                    counter!("synvoid.websocket.blocked").increment(1);
                    let _ = upstream_tx.close().await;
                    should_close_clone.stop();
                    break;
                }
                WafAction::LogOnly => {
                    tracing::debug!(
                        client_ip = %client_ip,
                        "WebSocket message logged by WAF"
                    );
                    counter!("synvoid.websocket.logged").increment(1);
                }
                WafAction::Allow => {}
                WafAction::Challenge | WafAction::Stall | WafAction::TarPit => {
                    tracing::debug!(
                        client_ip = %client_ip,
                        "WebSocket WAF action {:?} treated as allow",
                        action
                    );
                }
            }

            if let Err(e) = upstream_tx.send(msg).await {
                tracing::debug!("Upstream WebSocket send error: {}", e);
                break;
            }
        }
    };

    let upstream_to_client = async {
        while let Some(msg_result) = upstream_rx.next().await {
            if !should_close.is_running() {
                break;
            }

            let msg = match msg_result {
                Ok(m) => m,
                Err(e) => {
                    tracing::debug!("WebSocket upstream error: {}", e);
                    break;
                }
            };

            let (method, body_vec) = match &msg {
                tokio_tungstenite::tungstenite::Message::Text(t) => {
                    ("TEXT-RESPONSE", t.as_bytes().to_vec())
                }
                tokio_tungstenite::tungstenite::Message::Binary(b) => {
                    ("BINARY-RESPONSE", b.to_vec())
                }
                tokio_tungstenite::tungstenite::Message::Close(_) => {
                    let _ = client_tx.send(msg).await;
                    break;
                }
                tokio_tungstenite::tungstenite::Message::Ping(data) => {
                    let _ = client_tx
                        .send(tokio_tungstenite::tungstenite::Message::Pong(data.clone()))
                        .await;
                    continue;
                }
                tokio_tungstenite::tungstenite::Message::Pong(_) => continue,
                tokio_tungstenite::tungstenite::Message::Frame(_) => continue,
            };

            let mut proto_request = ProtocolRequest {
                client_ip: SocketAddr::from((client_ip, 0)),
                method: method.to_string(),
                path: "/upstream-response".to_string(),
                headers: HashMap::new(),
                body: body_vec,
                protocol: ProtocolType::WebSocket,
                metadata: HashMap::new(),
            };

            let action = ws_handler.apply_waf(&mut proto_request, &(waf_clone.clone() as Arc<dyn WafCoreBackend>));
            match action {
                WafAction::Block => {
                    tracing::warn!(
                        client_ip = %client_ip,
                        "WebSocket upstream response blocked by WAF"
                    );
                    counter!("synvoid.websocket.blocked").increment(1);
                    let _ = client_tx.close().await;
                    should_close.stop();
                    break;
                }
                WafAction::LogOnly => {
                    tracing::debug!(
                        client_ip = %client_ip,
                        "WebSocket upstream response logged by WAF"
                    );
                    counter!("synvoid.websocket.logged").increment(1);
                }
                WafAction::Allow => {}
                WafAction::Challenge | WafAction::Stall | WafAction::TarPit => {
                    tracing::debug!(
                        client_ip = %client_ip,
                        "WebSocket upstream response WAF action {:?} treated as allow",
                        action
                    );
                }
            }

            if let Err(e) = client_tx.send(msg).await {
                tracing::debug!("Client WebSocket send error: {}", e);
                break;
            }
        }
    };

    tokio::select! {
        _ = client_to_upstream => {}
        _ = upstream_to_client => {}
    }

    counter!("synvoid.websocket.closed").increment(1);
    tracing::debug!("WebSocket connection closed");
}

pub async fn handle_websocket_to_appserver(
    upgraded: hyper::upgrade::OnUpgrade,
    socket_path: std::path::PathBuf,
    _target: crate::router::RouteTarget,
    path: String,
    waf: Arc<WafCore>,
    client_ip: std::net::IpAddr,
    ws_config: SiteWebSocketConfig,
) {
    let upgraded = match upgraded.await {
        Ok(up) => up,
        Err(e) => {
            tracing::error!("WebSocket upgrade to AppServer failed: {}", e);
            counter!("synvoid.websocket.upgrade_failed").increment(1);
            return;
        }
    };

    counter!("synvoid.websocket.connections").increment(1);

    let ws_stream =
        WebSocketStream::from_raw_socket(TokioIo::new(upgraded), Role::Server, None).await;

    let (mut client_tx, mut client_rx) = ws_stream.split();

    let ws_handler = WebSocketHandler::new()
        .with_max_message_size(ws_config.max_message_size.unwrap_or(16 * 1024 * 1024))
        .with_mask_required(ws_config.mask_required.unwrap_or(false));

    let socket_url = format!("http://unix:{}:{}", socket_path.display(), path);

    tracing::debug!(url = %socket_url, "Connecting to AppServer WebSocket");

    let (upstream_ws, _) = match connect_async(&socket_url).await {
        Ok(ws) => ws,
        Err(e) => {
            tracing::error!("Failed to connect to AppServer WebSocket: {}", e);
            counter!("synvoid.websocket.upstream_failed").increment(1);
            return;
        }
    };

    counter!("synvoid.websocket.upstream_connected").increment(1);

    let (mut upstream_tx, mut upstream_rx) = upstream_ws.split();

    let path_clone = path.clone();
    let waf_clone = waf.clone();
    let should_close = std::sync::Arc::new(RunningFlag::new());
    let should_close_clone = should_close.clone();

    let client_to_upstream = async {
        while let Some(msg_result) = client_rx.next().await {
            if !should_close_clone.is_running() {
                break;
            }

            let msg = match msg_result {
                Ok(m) => m,
                Err(e) => {
                    tracing::debug!("WebSocket client error: {}", e);
                    break;
                }
            };

            let (method, body_vec) = match &msg {
                tokio_tungstenite::tungstenite::Message::Text(t) => ("TEXT", t.as_bytes().to_vec()),
                tokio_tungstenite::tungstenite::Message::Binary(b) => ("BINARY", b.to_vec()),
                tokio_tungstenite::tungstenite::Message::Close(_) => {
                    let _ = upstream_tx
                        .send(tokio_tungstenite::tungstenite::Message::Close(None))
                        .await;
                    break;
                }
                tokio_tungstenite::tungstenite::Message::Ping(data) => {
                    let _ = upstream_tx
                        .send(tokio_tungstenite::tungstenite::Message::Pong(data.clone()))
                        .await;
                    continue;
                }
                tokio_tungstenite::tungstenite::Message::Pong(_) => continue,
                tokio_tungstenite::tungstenite::Message::Frame(_) => continue,
            };

            let mut proto_request = ProtocolRequest {
                client_ip: SocketAddr::from((client_ip, 0)),
                method: method.to_string(),
                path: path_clone.clone(),
                headers: HashMap::new(),
                body: body_vec,
                protocol: ProtocolType::WebSocket,
                metadata: HashMap::new(),
            };

            let action = ws_handler.apply_waf(&mut proto_request, &(waf_clone.clone() as Arc<dyn WafCoreBackend>));
            match action {
                WafAction::Block => {
                    tracing::warn!(
                        client_ip = %client_ip,
                        "WebSocket message blocked by WAF"
                    );
                    counter!("synvoid.websocket.blocked").increment(1);
                    let _ = upstream_tx.close().await;
                    should_close_clone.stop();
                    break;
                }
                WafAction::LogOnly => {
                    tracing::debug!(
                        client_ip = %client_ip,
                        "WebSocket message logged by WAF"
                    );
                    counter!("synvoid.websocket.logged").increment(1);
                }
                WafAction::Allow => {}
                WafAction::Challenge | WafAction::Stall | WafAction::TarPit => {
                    tracing::debug!(
                        client_ip = %client_ip,
                        "WebSocket WAF action {:?} treated as allow",
                        action
                    );
                }
            }

            if let Err(e) = upstream_tx.send(msg).await {
                tracing::debug!("AppServer WebSocket send error: {}", e);
                break;
            }
        }
    };

    let upstream_to_client = async {
        while let Some(msg_result) = upstream_rx.next().await {
            if !should_close.is_running() {
                break;
            }

            let msg = match msg_result {
                Ok(m) => m,
                Err(e) => {
                    tracing::debug!("AppServer WebSocket upstream error: {}", e);
                    break;
                }
            };

            let (method, body_vec) = match &msg {
                tokio_tungstenite::tungstenite::Message::Text(t) => {
                    ("TEXT-RESPONSE", t.as_bytes().to_vec())
                }
                tokio_tungstenite::tungstenite::Message::Binary(b) => {
                    ("BINARY-RESPONSE", b.to_vec())
                }
                tokio_tungstenite::tungstenite::Message::Close(_) => {
                    let _ = client_tx.send(msg).await;
                    break;
                }
                tokio_tungstenite::tungstenite::Message::Ping(data) => {
                    let _ = client_tx
                        .send(tokio_tungstenite::tungstenite::Message::Pong(data.clone()))
                        .await;
                    continue;
                }
                tokio_tungstenite::tungstenite::Message::Pong(_) => continue,
                tokio_tungstenite::tungstenite::Message::Frame(_) => continue,
            };

            let mut proto_request = ProtocolRequest {
                client_ip: SocketAddr::from((client_ip, 0)),
                method: method.to_string(),
                path: "/appserver-response".to_string(),
                headers: HashMap::new(),
                body: body_vec,
                protocol: ProtocolType::WebSocket,
                metadata: HashMap::new(),
            };

            let action = ws_handler.apply_waf(&mut proto_request, &(waf_clone.clone() as Arc<dyn WafCoreBackend>));
            match action {
                WafAction::Block => {
                    tracing::warn!(
                        client_ip = %client_ip,
                        "WebSocket appserver response blocked by WAF"
                    );
                    counter!("synvoid.websocket.blocked").increment(1);
                    let _ = client_tx.close().await;
                    should_close.stop();
                    break;
                }
                WafAction::LogOnly => {
                    tracing::debug!(
                        client_ip = %client_ip,
                        "WebSocket appserver response logged by WAF"
                    );
                    counter!("synvoid.websocket.logged").increment(1);
                }
                WafAction::Allow => {}
                WafAction::Challenge | WafAction::Stall | WafAction::TarPit => {
                    tracing::debug!(
                        client_ip = %client_ip,
                        "WebSocket appserver response WAF action {:?} treated as allow",
                        action
                    );
                }
            }

            if let Err(e) = client_tx.send(msg).await {
                tracing::debug!("Client WebSocket send error: {}", e);
                break;
            }
        }
    };

    tokio::select! {
        _ = client_to_upstream => {}
        _ = upstream_to_client => {}
    }

    counter!("synvoid.websocket.closed").increment(1);
    tracing::debug!("AppServer WebSocket connection closed");
}
