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
use tokio::sync::broadcast::error::RecvError;

fn get_cookie_value(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .and_then(|cookie_str| {
            cookie_str.split(';').find_map(|c| {
                let c = c.trim();
                if c.starts_with(&format!("{}=", name)) {
                    Some(c[name.len() + 1..].to_string())
                } else {
                    None
                }
            })
        })
}

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

fn validate_session_cookie(headers: &HeaderMap, state: &AdminState) -> bool {
    let Some(session_id) = get_cookie_value(headers, super::SESSION_COOKIE_NAME) else {
        return false;
    };
    state.validate_session(&session_id)
}

pub async fn ws_metrics_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
) -> Response {
    let has_valid_auth = validate_bearer_token(&headers, &state.security.admin_token).is_ok()
        || validate_session_cookie(&headers, &state);

    if !has_valid_auth {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let broadcaster = state.metrics.metrics_broadcaster.clone();

    if broadcaster.client_count() >= broadcaster.max_clients() {
        return (StatusCode::SERVICE_UNAVAILABLE, "Max clients reached").into_response();
    }

    ws.on_upgrade(move |socket| handle_metrics_socket(socket, broadcaster))
}

pub async fn ws_logs_handler(
    ws: WebSocketUpgrade,
    State(state): State<Arc<AdminState>>,
    headers: HeaderMap,
) -> Response {
    let has_valid_auth = validate_bearer_token(&headers, &state.security.admin_token).is_ok()
        || validate_session_cookie(&headers, &state);

    if !has_valid_auth {
        return StatusCode::UNAUTHORIZED.into_response();
    }

    let broadcaster = state.metrics.logs_broadcaster.clone();

    if broadcaster.client_count() >= broadcaster.max_clients() {
        return (StatusCode::SERVICE_UNAVAILABLE, "Max clients reached").into_response();
    }

    ws.on_upgrade(move |socket| handle_logs_socket(socket, broadcaster))
}

async fn handle_metrics_socket(socket: WebSocket, broadcaster: Arc<broadcaster::Broadcaster>) {
    let (mut sender, mut receiver) = socket.split();
    let Some((client_id, mut rx)) = broadcaster.new_client() else {
        return;
    };

    super::metrics_events::ws_client_connected();
    tracing::debug!("WebSocket client {} connected to metrics", client_id);

    let client_id_clone = client_id.clone();
    let send_task = tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(msg) => {
                    if sender.send(Message::Text(msg.into())).await.is_err() {
                        break;
                    }
                }
                Err(RecvError::Lagged(_)) => {
                    tracing::warn!(
                        "Metrics WebSocket client {} lagged, continuing",
                        client_id_clone
                    );
                    super::metrics_events::record_ws_lagged();
                    continue;
                }
                Err(RecvError::Closed) => {
                    break;
                }
            }
        }
    });

    while let Some(msg) = receiver.next().await {
        if msg.is_err() {
            break;
        }
    }

    broadcaster.remove_client(&client_id);
    super::metrics_events::ws_client_disconnected();
    send_task.abort();

    tracing::debug!("WebSocket client {} disconnected from metrics", client_id);
}

async fn handle_logs_socket(socket: WebSocket, broadcaster: Arc<broadcaster::Broadcaster>) {
    let (mut sender, mut receiver) = socket.split();
    let Some((client_id, mut rx)) = broadcaster.new_client() else {
        return;
    };

    super::metrics_events::ws_client_connected();
    tracing::debug!("WebSocket client {} connected to logs", client_id);

    let client_id_clone = client_id.clone();
    let send_task = tokio::spawn(async move {
        loop {
            match rx.recv().await {
                Ok(msg) => {
                    if sender.send(Message::Text(msg.into())).await.is_err() {
                        break;
                    }
                }
                Err(RecvError::Lagged(_)) => {
                    tracing::warn!(
                        "Logs WebSocket client {} lagged, continuing",
                        client_id_clone
                    );
                    super::metrics_events::record_ws_lagged();
                    continue;
                }
                Err(RecvError::Closed) => {
                    break;
                }
            }
        }
    });

    while let Some(msg) = receiver.next().await {
        if msg.is_err() {
            break;
        }
    }

    broadcaster.remove_client(&client_id);
    super::metrics_events::ws_client_disconnected();
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

    #[test]
    fn test_validate_session_cookie_no_cookie() {
        let headers = axum::http::HeaderMap::new();
        let config_dir = std::env::temp_dir();
        let config = std::sync::Arc::new(tokio::sync::RwLock::new(
            crate::config::ConfigManager::new(config_dir),
        ));
        let state = crate::admin::state::AdminState::new(config, "test".to_string());
        assert!(!validate_session_cookie(&headers, &state));
    }

    #[test]
    fn test_validate_session_cookie_invalid_session() {
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            "cookie",
            "synvoid_session=invalid_nonexistent_session"
                .parse()
                .unwrap(),
        );
        let config_dir = std::env::temp_dir();
        let config = std::sync::Arc::new(tokio::sync::RwLock::new(
            crate::config::ConfigManager::new(config_dir),
        ));
        let state = crate::admin::state::AdminState::new(config, "test".to_string());
        assert!(!validate_session_cookie(&headers, &state));
    }

    #[test]
    fn test_validate_session_cookie_valid_session() {
        let config_dir = std::env::temp_dir();
        let config = std::sync::Arc::new(tokio::sync::RwLock::new(
            crate::config::ConfigManager::new(config_dir),
        ));
        let state = crate::admin::state::AdminState::new(config, "test".to_string());
        let session_id = state.create_session();

        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            "cookie",
            format!("synvoid_session={}", session_id).parse().unwrap(),
        );

        assert!(validate_session_cookie(&headers, &state));
    }

    #[test]
    fn test_no_synvoid_ws_token_cookie_accepted() {
        let config_dir = std::env::temp_dir();
        let config = std::sync::Arc::new(tokio::sync::RwLock::new(
            crate::config::ConfigManager::new(config_dir),
        ));
        let state = crate::admin::state::AdminState::new(config, "test".to_string());

        let mut headers = axum::http::HeaderMap::new();
        headers.insert("cookie", "synvoid_ws_token=some_raw_token".parse().unwrap());

        assert!(!validate_session_cookie(&headers, &state));
    }
}
