pub mod broadcaster;

use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    response::Response,
};
use axum_extra::{
    headers::{Authorization, authorization::Bearer},
    TypedHeader,
};
use futures::{SinkExt, StreamExt};
use std::sync::Arc;
use super::state::AdminState;
use super::auth::require_auth;

pub async fn ws_metrics_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AdminState>>,
    auth: Option<TypedHeader<Authorization<Bearer>>>,
) -> Response {
    if !require_auth(&auth, &state.admin_token, None) {
        return axum::response::IntoResponse::into_response(axum::http::StatusCode::UNAUTHORIZED);
    }
    
    ws.on_upgrade(move |socket| handle_metrics_socket(socket, state.metrics_broadcaster.clone()))
}

pub async fn ws_logs_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AdminState>>,
    auth: Option<TypedHeader<Authorization<Bearer>>>,
) -> Response {
    if !require_auth(&auth, &state.admin_token, None) {
        return axum::response::IntoResponse::into_response(axum::http::StatusCode::UNAUTHORIZED);
    }
    
    ws.on_upgrade(move |socket| handle_logs_socket(socket, state.logs_broadcaster.clone()))
}

async fn handle_metrics_socket(socket: WebSocket, broadcaster: Arc<broadcaster::Broadcaster>) {
    let (mut sender, mut receiver) = socket.split();
    let (client_id, mut rx) = broadcaster.new_client();
    
    tracing::debug!("WebSocket client {} connected to metrics", client_id);
    
    let send_task = tokio::spawn(async move {
        while let Ok(msg) = rx.recv().await {
            if sender.send(Message::Text(msg.into())).await.is_err() {
                break;
            }
        }
    });
    
    while let Some(msg) = receiver.next().await {
        if msg.is_err() {
            break;
        }
    }
    
    broadcaster.remove_client(&client_id);
    send_task.abort();
    
    tracing::debug!("WebSocket client {} disconnected from metrics", client_id);
}

async fn handle_logs_socket(socket: WebSocket, broadcaster: Arc<broadcaster::Broadcaster>) {
    let (mut sender, mut receiver) = socket.split();
    let (client_id, mut rx) = broadcaster.new_client();
    
    tracing::debug!("WebSocket client {} connected to logs", client_id);
    
    let send_task = tokio::spawn(async move {
        while let Ok(msg) = rx.recv().await {
            if sender.send(Message::Text(msg.into())).await.is_err() {
                break;
            }
        }
    });
    
    while let Some(msg) = receiver.next().await {
        if msg.is_err() {
            break;
        }
    }
    
    broadcaster.remove_client(&client_id);
    send_task.abort();
    
    tracing::debug!("WebSocket client {} disconnected from logs", client_id);
}
