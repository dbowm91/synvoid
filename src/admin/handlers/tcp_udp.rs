use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use super::super::state::AdminState;
use super::super::auth::{require_auth, OptionalAuth};

#[derive(Debug, Serialize)]
pub struct TcpUdpListener {
    pub id: String,
    pub port: u16,
    pub protocol: String,
    pub upstream: String,
    pub enabled: bool,
    pub active_connections: usize,
}

#[derive(Debug, Serialize)]
pub struct ListListenersResponse {
    pub listeners: Vec<TcpUdpListener>,
}

pub async fn list_listeners(
    State(state): State<Arc<AdminState>>,
    auth: OptionalAuth,
) -> Result<Json<ListListenersResponse>, StatusCode> {
    if !require_auth(&auth, &state.admin_token) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let config = state.config.read().await;
    let mut listeners = Vec::new();

    for (site_id, site_config) in &config.sites {
        for (name, port_config) in &site_config.tcp.ports {
            if let (Some(port), Some(upstream)) = (port_config.port, &port_config.upstream) {
                listeners.push(TcpUdpListener {
                    id: format!("{}-{}", site_id, name),
                    port,
                    protocol: name.clone(),
                    upstream: upstream.clone(),
                    enabled: site_config.tcp.enabled.unwrap_or(false),
                    active_connections: 0,
                });
            }
        }
    }

    Ok(Json(ListListenersResponse { listeners }))
}

#[derive(Debug, Deserialize)]
pub struct CreateListenerRequest {
    pub site_id: String,
    pub port: u16,
    pub protocol: String,
    pub upstream: String,
}

#[derive(Debug, Serialize)]
pub struct CreateListenerResponse {
    pub listener: TcpUdpListener,
}

pub async fn create_listener(
    State(state): State<Arc<AdminState>>,
    auth: OptionalAuth,
    Json(req): Json<CreateListenerRequest>,
) -> Result<Json<CreateListenerResponse>, StatusCode> {
    if !require_auth(&auth, &state.admin_token) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let listener = TcpUdpListener {
        id: format!("{}-{}", req.site_id, req.protocol),
        port: req.port,
        protocol: req.protocol,
        upstream: req.upstream,
        enabled: true,
        active_connections: 0,
    };

    Ok(Json(CreateListenerResponse { listener }))
}

pub async fn delete_listener(
    State(state): State<Arc<AdminState>>,
    auth: OptionalAuth,
    Path(listener_id): Path<String>,
) -> Result<StatusCode, StatusCode> {
    if !require_auth(&auth, &state.admin_token) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    tracing::info!("Deleting listener: {}", listener_id);
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Debug, Serialize)]
pub struct ProtocolInfo {
    pub name: String,
    pub description: String,
    pub default_ports: Vec<u16>,
}

pub async fn list_protocols(
    State(state): State<Arc<AdminState>>,
    auth: OptionalAuth,
) -> Result<Json<Vec<ProtocolInfo>>, StatusCode> {
    if !require_auth(&auth, &state.admin_token) {
        return Err(StatusCode::UNAUTHORIZED);
    }

    let protocols = vec![
        ProtocolInfo {
            name: "http".to_string(),
            description: "HTTP protocol detection".to_string(),
            default_ports: vec![80, 443, 8080],
        },
        ProtocolInfo {
            name: "smtp".to_string(),
            description: "SMTP mail protocol".to_string(),
            default_ports: vec![25, 587, 465],
        },
        ProtocolInfo {
            name: "imap".to_string(),
            description: "IMAP mail protocol".to_string(),
            default_ports: vec![143, 993],
        },
        ProtocolInfo {
            name: "mysql".to_string(),
            description: "MySQL database protocol".to_string(),
            default_ports: vec![3306],
        },
        ProtocolInfo {
            name: "postgres".to_string(),
            description: "PostgreSQL database protocol".to_string(),
            default_ports: vec![5432],
        },
    ];

    Ok(Json(protocols))
}
