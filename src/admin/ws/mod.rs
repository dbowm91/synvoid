pub mod broadcaster;

use super::auth::verify_admin_token;
use super::state::AdminState;
use axum::{
    extract::{
        ws::{Message, WebSocket, WebSocketUpgrade},
        State,
    },
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
};
use futures::{SinkExt, StreamExt};
use std::sync::Arc;

fn validate_bearer_token(headers: &HeaderMap, admin_token: &str) -> Result<(), StatusCode> {
    let bearer_token = headers
        .get(axum::http::header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .ok_or(StatusCode::UNAUTHORIZED)?;

    if verify_admin_token(bearer_token, admin_token) {
        Ok(())
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

pub async fn ws_metrics_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
) -> Response {
    if let Err(status) = validate_bearer_token(&headers, &state.security.admin_token) {
        return status.into_response();
    }
    ws.on_upgrade(move |socket| {
        handle_metrics_socket(socket, state.metrics.metrics_broadcaster.clone())
    })
}

pub async fn ws_logs_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
) -> Response {
    if let Err(status) = validate_bearer_token(&headers, &state.security.admin_token) {
        return status.into_response();
    }
    ws.on_upgrade(move |socket| handle_logs_socket(socket, state.metrics.logs_broadcaster.clone()))
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_bearer_token_no_header() {
        let headers = axum::http::HeaderMap::new();
        let result = validate_bearer_token(&headers, "test_hash");
        assert!(result.is_err());
        assert_eq!(result.unwrap_err(), StatusCode::UNAUTHORIZED);
    }

    #[test]
    fn test_validate_bearer_token_invalid_format() {
        use axum::http::header::AUTHORIZATION;

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(AUTHORIZATION, "Basic abc".parse().unwrap());

        let result = validate_bearer_token(&headers, "test_hash");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_bearer_token_wrong_token() {
        use axum::http::header::AUTHORIZATION;

        let token = "correct_token";
        let hash = crate::admin::auth::hash_admin_token(token).unwrap();

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(AUTHORIZATION, format!("Bearer {}", hash).parse().unwrap());

        let result = validate_bearer_token(&headers, "wrong_token");
        assert!(result.is_err());
    }

    #[test]
    fn test_validate_bearer_token_correct() {
        use axum::http::header::AUTHORIZATION;

        let token = "my_admin_token";
        let hash = crate::admin::auth::hash_admin_token(token).unwrap();

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(AUTHORIZATION, format!("Bearer {}", token).parse().unwrap());

        let result = validate_bearer_token(&headers, &hash);
        assert!(result.is_ok());
    }
}
