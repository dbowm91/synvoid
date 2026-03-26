use axum::{
    extract::{Path, State},
    http::StatusCode,
    Json,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use super::super::state::AdminState;
use super::common::{OptionalAuth};

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct TcpUdpListener {
    pub id: String,
    pub port: u16,
    pub protocol: String,
    pub upstream: String,
    pub enabled: bool,
    pub active_connections: usize,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ListListenersResponse {
    pub listeners: Vec<TcpUdpListener>,
}

#[utoipa::path(
    get,
    path = "/tcp-udp/listeners",
    tag = "TCP/UDP",
    responses(
        (status = 200, description = "List of TCP/UDP listeners", body = [ListListenersResponse]),
        (status = 401, description = "Unauthorized - missing or invalid bearer token")
    ),
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn list_listeners(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<ListListenersResponse>, StatusCode> {

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

#[derive(Debug, Deserialize, utoipa::ToSchema)]
pub struct CreateListenerRequest {
    pub site_id: String,
    pub port: u16,
    pub protocol: String,
    pub upstream: String,
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct CreateListenerResponse {
    pub listener: TcpUdpListener,
}

#[utoipa::path(
    post,
    path = "/tcp-udp/listeners",
    tag = "TCP/UDP",
    responses(
        (status = 200, description = "Listener created", body = [CreateListenerResponse]),
        (status = 401, description = "Unauthorized - missing or invalid bearer token")
    ),
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn create_listener(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Json(req): Json<CreateListenerRequest>,
) -> Result<Json<CreateListenerResponse>, StatusCode> {

    tracing::warn!(
        "create_listener called for {}/{} but is not yet implemented",
        req.site_id, req.protocol
    );
    
    Err(StatusCode::NOT_IMPLEMENTED)
}

#[utoipa::path(
    delete,
    path = "/tcp-udp/listeners/{listener_id}",
    tag = "TCP/UDP",
    params(
        ("listener_id" = String, Path, description = "Listener ID to delete")
    ),
    responses(
        (status = 204, description = "Listener deleted successfully"),
        (status = 401, description = "Unauthorized - missing or invalid bearer token"),
        (status = 404, description = "Listener not found")
    ),
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn delete_listener(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
    Path(listener_id): Path<String>,
) -> Result<StatusCode, StatusCode> {

    tracing::warn!(
        "delete_listener called for {} but is not yet implemented",
        listener_id
    );
    
    Err(StatusCode::NOT_IMPLEMENTED)
}

#[derive(Debug, Serialize, utoipa::ToSchema)]
pub struct ProtocolInfo {
    pub name: String,
    pub description: String,
    pub supported: bool,
}

#[utoipa::path(
    get,
    path = "/tcp-udp/protocols",
    tag = "TCP/UDP",
    responses(
        (status = 200, description = "List of supported protocols", body = [ProtocolInfo]),
        (status = 401, description = "Unauthorized - missing or invalid bearer token")
    ),
    security(
        ("bearerAuth" = [])
    )
)]
pub async fn list_protocols(
    State(state): State<Arc<AdminState>>,
    _auth: OptionalAuth,
) -> Result<Json<Vec<ProtocolInfo>>, StatusCode> {

    let protocols = vec![
        ProtocolInfo {
            name: "http".to_string(),
            description: "HTTP/1.1 proxy".to_string(),
            supported: true,
        },
        ProtocolInfo {
            name: "http2".to_string(),
            description: "HTTP/2 proxy".to_string(),
            supported: true,
        },
        ProtocolInfo {
            name: "tls".to_string(),
            description: "TLS/SSL proxy".to_string(),
            supported: true,
        },
    ];

    Ok(Json(protocols))
}
